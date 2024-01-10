import os
import git
import sys
import json
import time
import base64
import gevent
import logging
import argparse
import platform
import requests
import functools
import traceback
import subprocess
from pathlib import Path
from steam.enums import EResult
from push import push, push_data
from multiprocessing.pool import ThreadPool
from multiprocessing.dummy import Pool, Lock
from steam.guard import generate_twofactor_code
from DepotManifestGen.main import MySteamClient, MyCDNClient, get_manifest, BillingType, Result

lock = Lock()
sys.setrecursionlimit(100000)
parser = argparse.ArgumentParser()
parser.add_argument('-c', '--credential-location', default=None)
parser.add_argument('-l', '--level', default='INFO')
parser.add_argument('-p', '--pool-num', type=int, default=8)
parser.add_argument('-r', '--retry-num', type=int, default=3)
parser.add_argument('-t', '--update-wait-time', type=int, default=86400)
parser.add_argument('-k', '--key', default=None)
parser.add_argument('-i', '--init-only', action='store_true', default=False)
parser.add_argument('-C', '--cli', action='store_true', default=False)
parser.add_argument('-P', '--no-push', action='store_true', default=False)
parser.add_argument('-u', '--update', action='store_true', default=False)
parser.add_argument('-a', '--app-id', dest='app_id_list', action='extend', nargs='*')
parser.add_argument('-U', '--users', dest='user_list', action='extend', nargs='*')


class MyJson(dict):
    """
    MyJson类用于处理JSON文件的加载和保存

    Attributes:
        path (Path): JSON文件路径

    Methods:
        __init__(self, path): 初始化方法，加载JSON文件
        load(self): 加载JSON文件
        dump(self): 保存JSON文件
    """

    def __init__(self, path):
        """
        初始化方法，加载JSON文件

        Args:
            path (str): JSON文件路径
        """
        super().__init__()
        self.path = Path(path)
        self.load()

    def load(self):
        """
        加载JSON文件

        Returns:
            None
        """
        if not self.path.exists():
            self.dump()
            return
        with self.path.open() as f:
            self.update(json.load(f))

    def dump(self):
        """
        保存JSON文件

        Returns:
            None
        """
        with self.path.open('w') as f:
            json.dump(self, f)


class LogExceptions:
    def __init__(self, fun):
        # 构造函数，接受一个函数作为参数
        self.__callable = fun
        return

    def __call__(self, *args, **kwargs):
        # __call__方法，用于调用该类实例时自动调用类中的函数
        try:
            return self.__callable(*args, **kwargs)
        except KeyboardInterrupt:
            # 捕获键盘中断异常，并重新抛出
            raise
        except:
            # 捕获其他异常，记录错误日志并打印完整错误信息
            logging.error(traceback.format_exc())


class ManifestAutoUpdate:
    log = logging.getLogger('ManifestAutoUpdate')
    ROOT = Path('data').absolute()
    users_path = ROOT / Path('users.json')
    app_info_path = ROOT / Path('appinfo.json')
    user_info_path = ROOT / Path('userinfo.json')
    two_factor_path = ROOT / Path('2fa.json')
    key_path = ROOT / 'KEY'
    git_crypt_path = ROOT / ('git-crypt' + ('.exe' if platform.system().lower() == 'windows' else ''))
    repo = git.Repo()
    app_lock = {}
    pool_num = 8
    retry_num = 3
    remote_head = {}

    def __init__(self, credential_location=None, level=None, pool_num=None, retry_num=None, update_wait_time=None,
                 key=None, init_only=False, cli=False, app_id_list=None, user_list=None):
        """
        初始化函数，用于设置和配置库的属性和参数

        :param credential_location: str，凭证文件的位置
        :param level: str 或 int，日志级别
        :param pool_num: int，连接池的数量
        :param retry_num: int，重试次数
        :param update_wait_time: int，更新等待时间
        :param key: str，密钥
        :param init_only: bool，是否只进行初始化
        :param cli: bool，是否为CLI模式
        :param app_id_list: list，应用ID列表
        :param user_list: list，用户列表
        """
        # 设置日志级别，如果没有给出级别，则默认为INFO级别
        if level:
            level = logging.getLevelName(level.upper())
        else:
            level = logging.INFO
        # 设置日志格式并初始化日志
        logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                            level=level)
        # 设置MySteamClient的日志级别为WARNING
        logging.getLogger('MySteamClient').setLevel(logging.WARNING)

        # 初始化属性
        self.init_only = init_only
        self.cli = cli
        self.pool_num = pool_num or self.pool_num
        self.retry_num = retry_num or self.retry_num
        self.update_wait_time = update_wait_time or self.update_wait_time
        self.credential_location = Path(credential_location or self.ROOT / 'client')
        self.key = key

        # 检查并设置app_sha
        self.app_sha = self.get_app_sha('app')
        self.app_sha = self.app_sha or self.get_app_sha('app')

        # 检查并设置data仓库
        self.get_data_repo()

        # 检查并解锁git-crypt
        self.unlock_git_crypt()

        # 创建目录并初始化属性
        self.credential_location.mkdir(exist_ok=True)
        self.account_info = MyJson(self.users_path)
        self.user_info = MyJson(self.user_info_path)
        self.app_info = MyJson(self.app_info_path)
        self.two_factor = MyJson(self.two_factor_path)

        # 获取远程标签并更新用户列表和应用ID列表
        self.get_remote_tags()
        self.update_user_list = [*user_list] if user_list else []
        self.update_app_id_list = []
        if app_id_list:
            self.update_app_id_list = list(set(int(i) for i in app_id_list if i.isdecimal()))
            for user, info in self.user_info.items():
                if info['enable'] and info['app']:
                    for app_id in info['app']:
                        if app_id in self.update_app_id_list:
                            self.update_user_list.append(user)
        self.update_user_list = list(set(self.update_user_list))


    update_wait_time = 86400
    tags = set()

    def download_git_crypt(self):
        # 检查git-crypt是否已下载
        if self.git_crypt_path.exists():
            return

        # 信息日志：等待下载git-crypt!
        self.log.info('等待下载git-crypt!')

        # 设置下载链接
        url = 'https://github.com/AGWA/git-crypt/releases/download/0.7.0/'
        url_win = 'git-crypt-0.7.0-x86_64.exe'
        url_linux = 'git-crypt-0.7.0-linux-x86_64'

        # 根据操作系统选择合适的下载链接
        url = url + (url_win if platform.system().lower() == 'windows' else url_linux)

        try:
            # 发送请求，下载git-crypt安装文件
            r = requests.get(url)
            with self.git_crypt_path.open('wb') as f:
                f.write(r.content)

            # 对非Windows系统进行可执行权限添加
            if platform.system().lower() != 'windows':
                subprocess.run(['chmod', '+x', self.git_crypt_path])
        except requests.exceptions.ConnectionError:
            # 请求连接错误处理
            traceback.print_exc()
            exit()

    def get_manifest_callback(self, username, app_id, depot_id, manifest_gid, args):
        """
        获取manifest回调函数

        Args:
            self: 当前类实例
            username: 用户名
            app_id: 应用ID
            depot_id: 仓库ID
            manifest_gid: manifest GID
            args: 参数

        Returns:
            None

        Raises:
            None
        """
        result = args.value
        if not result:
            self.log.warning(f'User {username}: get_manifest return {result.code.__repr__()}')
            return
        app_path = self.ROOT / f'depots/{app_id}'
        try:
            delete_list = result.get('delete_list') or []
            manifest_commit = result.get('manifest_commit')
            if len(delete_list) > 1:
                self.log.warning('Deleted multiple files?')
            self.set_depot_info(depot_id, manifest_gid)
            app_repo = git.Repo(app_path)
            with lock:
                if manifest_commit:
                    app_repo.create_tag(f'{depot_id}_{manifest_gid}', manifest_commit)
                else:
                    if delete_list:
                        app_repo.git.rm(delete_list)
                    app_repo.git.add(f'{depot_id}_{manifest_gid}.manifest')
                    app_repo.git.add('config.vdf')
                    app_repo.index.commit(f'Update depot: {depot_id}_{manifest_gid}')
                    app_repo.create_tag(f'{depot_id}_{manifest_gid}')
        except KeyboardInterrupt:
            raise
        except:
            logging.error(traceback.format_exc())
        finally:
            with lock:
                if int(app_id) in self.app_lock:
                    self.app_lock[int(app_id)].remove(depot_id)
                    if int(app_id) not in self.user_info[username]['app']:
                        self.user_info[username]['app'].append(int(app_id))
                    if not self.app_lock[int(app_id)]:
                        self.log.debug(f'Unlock app: {app_id}')
                        self.app_lock.pop(int(app_id))

    def set_depot_info(self, depot_id, manifest_gid):
        '''
        设置仓库信息

        Args:
            depot_id (int): 仓库ID
            manifest_gid (str): manifest GID

        Returns:
            None
        '''
        with lock:
            self.app_info[depot_id] = manifest_gid

    def save_user_info(self):
        """
        保存用户信息的方法

        该方法用于将用户信息保存到文件中。

        Args:
            无

        Returns:
            无
        """
        with lock:
            self.user_info.dump()

    def save(self):
        # 保存仓库信息
        self.save_depot_info()
        # 保存用户信息
        self.save_user_info()

    def save_depot_info(self):
        """
        保存仓库信息的方法。

        这个方法用于将 app_info 对象的数据保存下来。
        """
        with lock:
            self.app_info.dump()

    # 该函数用于获取应用的工作树信息，并返回一个字典。函数内部使用锁确保线程安全。首先，函数内部定义一个空字典worktree_dict。然后，使用self.repo.git.worktree(
    #     'list')
    # 命令获取工作树列表，并使用\n分割成字符串列表worktree_list。接下来，使用for循环遍历worktree_list，将每个工作树字符串按空格分割，获取路径、HEAD、名称等信息，并将名称去除括号后作为键。如果名称不是十进制数字，则跳过该工作树。否则，将路径和HEAD作为值，以名称作为键，添加到worktree_dict字典中。最后，返回worktree_dict字典。
    def get_app_worktree(self):
        worktree_dict = {}
        with lock:  # 使用锁确保线程安全
            worktree_list = self.repo.git.worktree('list').split('\n')  # 获取工作树列表并按换行符分割成列表
        for worktree in worktree_list:  # 遍历工作树列表
            path, head, name, *_ = worktree.split()  # 将工作树字符串按空格分割成列表，并获取路径、HEAD、名称等信息
            name = name[1:-1]  # 获取去除括号后的名称
            if not name.isdecimal():  # 如果名称不是十进制数字，则跳过
                continue
            worktree_dict[name] = (path, head)  # 将路径和HEAD添加到工作树字典中，以名称为键
        return worktree_dict  # 返回工作树字典

    def get_remote_head(self):
        # 如果已经存在远程分支的 HEAD，则直接返回
        if self.remote_head:
            return self.remote_head
        # 创建一个字典来保存远程分支和对应的 HEAD
        head_dict = {}
        # 使用 git.ls_remote() 命令获取远程分支信息，并按换行符分割成列表
        for i in self.repo.git.ls_remote('--head', 'origin').split('\n'):
            # 将每个分支信息按空格分割，并取第二个元素作为分支名
            commit, head = i.split()
            head = head.split('/')[2]
            # 将分支名和对应的 COMMIT 添加到字典中
            head_dict[head] = commit
        # 将保存好的远程分支信息赋值给实例变量
        self.remote_head = head_dict
        # 返回远程分支信息字典
        return head_dict

    def check_app_repo_remote(self, repo):
        """
        检查应用仓库是否具有远程 HEAD
        :param repo: 应用仓库对象
        :return: True - 有远程 HEAD; False - 无远程 HEAD
        """
        return str(repo) in self.get_remote_head()

    def check_app_repo_local(self, repo):
        """
        检查本地仓库中是否存在指定的分支。

        参数：
        self (object): 类自身引用
        repo (str): 要检查的分支名称

        返回值：
        bool: 如果本地仓库中存在指定的分支，则返回True；否则返回False。
        """
        for branch in self.repo.heads:
            if branch.name == str(repo):
                return True
        return False

    def get_remote_tags(self):
        # 获取远程标签
        if not self.tags:
            # 如果标签列表为空
            for i in filter(None, self.repo.git.ls_remote('--tags').split('\n')):
                # 遍历过滤掉空字符串后的标签列表
                sha, tag = i.split()
                # 分割 SHA 值和标签值
                tag = tag.split('/')[-1]
                # 获取最后一个斜杠后的字符串作为标签名
                self.tags.add(tag)
                # 将标签名添加到标签集合中
        return self.tags
        # 返回标签集合

    def check_manifest_exist(self, depot_id, manifest_gid):
        """
        检查是否存在指定的清单
        :param depot_id: 仓库ID
        :param manifest_gid: 命名空间ID
        :return: 存在则返回True，否则返回False
        """
        for tag in set([i.name for i in self.repo.tags] + [*self.tags]):
            if f'{depot_id}_{manifest_gid}' == tag:
                return True
        return False

    def init_app_repo(self, app_id):
        """
        初始化应用程序仓库

        :param app_id: 应用程序ID
        """
        app_path = self.ROOT / f'depots/{app_id}'

        # 如果应用程序工作目录中不存在该应用程序，则进行以下操作
        if str(app_id) not in self.get_app_worktree():
            if app_path.exists():
                app_path.unlink(missing_ok=True)

            # 如果应用程序远程仓库存在，则拉取远程仓库的代码
            if self.check_app_repo_remote(app_id):
                with lock:
                    # 如果本地仓库中不存在该应用程序，则先从远程仓库拉取代码
                    if not self.check_app_repo_local(app_id):
                        self.repo.git.fetch('origin', f'{app_id}:origin_{app_id}')

                # 将指定分支的代码添加为本地工作目录
                self.repo.git.worktree('add', '-b', app_id, app_path, f'origin_{app_id}')

            # 如果应用程序远程仓库不存在，则将默认分支添加为本地工作目录
            else:
                # 如果本地仓库中存在该应用程序分支，则先删除该分支
                if self.check_app_repo_local(app_id):
                    self.log.warning(f'Branch {app_id} does not exist locally and remotely!')
                    self.repo.git.branch('-d', app_id)

                # 将默认分支添加为本地工作目录
                self.repo.git.worktree('add', '-b', app_id, app_path, 'app')

    def retry(self, fun, *args, retry_num=-1, **kwargs):
        """
        重复执行指定的函数直到成功或达到重试次数限制

        Args:
            fun: 要重复执行的函数
            *args: 函数的位置参数
            retry_num: 重试次数，默认为-1表示无限次重试
            **kwargs: 函数的关键字参数

        Returns:
            函数的返回值，如果执行成功
        """

        while retry_num:
            try:
                return fun(*args, **kwargs)
            except gevent.timeout.Timeout as e:
                retry_num -= 1
                self.log.warning(e)
            except Exception as e:
                self.log.error(e)
                return

    def login(self, steam, username, password):

        """
        登录账户

        Args:
            steam: Steam对象，用于登录操作
            username: 用户名，要登录的账户
            password: 密码，用于账户登录验证

        Returns:
            EResult.OK if login is successful, otherwise the corresponding EResult value
        """
        self.log.info(f'Logging in to account {username}!')  # 打印日志，显示正在登录的账户

        # 获取用户的两因素认证码
        shared_secret = self.two_factor.get(username)

        steam.username = username  # 设置Steam对象的用户名为给定的用户名
        result = steam.relogin()  # 重新登录Steam账号

        wait = 1  # 设置等待时间初始值为1秒

        # 如果重新登录结果不为OK，则进行相应处理
        if result != EResult.OK:
            if result != EResult.Fail:
                self.log.warning(f'User {username}: Relogin failure reason: {result.__repr__()}')  # 打印警告日志，显示重新登录失败的原因
            if result == EResult.RateLimitExceeded:
                with lock:
                    time.sleep(wait)  # 如果重新登录结果为RateLimitExceeded，则等待一段时间后再次尝试登录
            result = steam.login(username, password, steam.login_key, two_factor_code=generate_twofactor_code(
                base64.b64decode(shared_secret)) if shared_secret else None)  # 登录账户

        count = self.retry_num  # 设置重试次数为retry_num

        # 循环直到登录成功或者重试次数用尽
        while result != EResult.OK and count:
            if self.cli:
                with lock:
                    self.log.warning(
                        f'Using the command line to interactively log in to account {username}!')  # 打印警告日志，显示使用命令行进行交互式登录
                    result = steam.cli_login(username, password)  # 使用命令行进行交互式登录
                break
            elif result == EResult.RateLimitExceeded:
                if not count:
                    break
                with lock:
                    time.sleep(wait)
                result = steam.login(username, password, steam.login_key, two_factor_code=generate_twofactor_code(
                    base64.b64decode(shared_secret)) if shared_secret else None)  # 登录账户
            elif result in (EResult.AccountLogonDenied, EResult.AccountDisabled,
                            EResult.AccountLoginDeniedNeedTwoFactor, EResult.PasswordUnset):
                logging.warning(f'User {username} has been disabled!')  # 打印警告日志，显示用户已被禁用
                self.user_info[username]['enable'] = False  # 在用户信息中禁用用户账户
                self.user_info[username]['status'] = result  # 在用户信息中存储账户状态
                break
            wait += 1  # 增加等待时间
            count -= 1  # 重试次数减一
            self.log.error(f'User {username}: Login failure reason: {result.__repr__()}')  # 打印错误日志，显示登录失败的原因

        # 如果登录成功，打印成功日志，否则打印失败日志

    def async_task(self, cdn, app_id, depot_id, manifest_gid):
        # 初始化应用仓库
        self.init_app_repo(app_id)
        # 构建manifest文件路径
        manifest_path = self.ROOT / f'depots/{app_id}/{depot_id}_{manifest_gid}.manifest'
        if manifest_path.exists():
            # 如果manifest文件路径存在
            self.log.debug(f'manifest_path exists: {manifest_path}')
            # 创建应用仓库对象
            app_repo = git.Repo(self.ROOT / f'depots/{app_id}')
            try:
                # 尝试获取最近一次修改manifest文件的提交ID
                manifest_commit = app_repo.git.rev_list('-1', str(app_id),
                                                        f'{depot_id}_{manifest_gid}.manifest').strip()
            except git.exc.GitCommandError:
                # 如果获取提交ID失败，则删除manifest文件路径
                manifest_path.unlink(missing_ok=True)
            else:
                # 如果获取提交ID成功
                self.log.debug(f'manifest_commit: {manifest_commit}')
                # 返回结果对象，包含应用ID、仓库ID、manifest提交ID等信息
                return Result(result=True, app_id=app_id, depot_id=depot_id, manifest_gid=manifest_gid,
                              manifest_commit=manifest_commit)
        # 如果manifest文件路径不存在，则调用其他函数获取manifest文件
        return get_manifest(cdn, app_id, depot_id, manifest_gid, True, self.ROOT, self.retry_num)


    def get_manifest(self, username, password, sentry_name=None):
        with lock:  # 使用互斥锁确保线程安全
            if username not in self.user_info:  # 如果用户信息不存在
                self.user_info[username] = {}  # 创建以用户名为键的字典
                self.user_info[username]['app'] = []  # 初始化用户的app列表
            if 'update' not in self.user_info[username]:  # 如果用户上次更新时间不存在
                self.user_info[username]['update'] = 0  # 设置为0
            if 'enable' not in self.user_info[username]:  # 如果用户是否启用不存在
                self.user_info[username]['enable'] = True  # 设置为True
            if not self.user_info[username]['enable']:  # 如果用户被禁用
                logging.warning(f'User {username} is disabled!')  # 记录警告日志
                return  # 返回

        t = self.user_info[username]['update'] + self.update_wait_time - time.time()  # 计算下次更新的时间间隔
        if t > 0:  # 如果时间间隔大于0
            logging.warning(f'User {username} interval from next update: {int(t)}s!')  # 记录警告日志
            return  # 返回

        sentry_path = None  # 初始化sentry路径
        if sentry_name:  # 如果sentry名称存在
            sentry_path = Path(
                self.credential_location if self.credential_location else MySteamClient.credential_location) / sentry_name  # 根据sentry名称计算sentry路径
        self.log.debug(f'User {username} sentry_path: {sentry_path}')  # 记录调试日志

        steam = MySteamClient(str(self.credential_location), sentry_path)  # 创建MySteamClient对象
        result = self.login(steam, username, password)  # 登录Steam
        if result != EResult.OK:  # 如果登录失败
            return  # 返回

        self.log.info(f'User {username}: Waiting to initialize the cdn client!')  # 记录信息日志
        cdn = self.retry(MyCDNClient, steam, retry_num=self.retry_num)  # 初始化CDN客户端
        if not cdn:  # 如果CDN客户端初始化失败
            logging.error(f'User {username}: Failed to initialize cdn!')  # 记录错误日志
            return  # 返回

        app_id_list = []  # 初始化appID列表
        if cdn.packages_info:  # 如果有安装包信息
            self.log.info(f'User {username}: Waiting to get packages info!')  # 记录信息日志
            product_info = self.retry(steam.get_product_info, packages=cdn.packages_info, retry_num=self.retry_num)  # 获取产品信息
            if not product_info:  # 如果获取失败
                logging.error(f'User {username}: Failed to get packages info!')  # 记录错误日志
                return  # 返回
            if cdn.packages_info:  # 如果有安装包信息
                for package_id, info in product_info['packages'].items():  # 遍历安装包信息
                    if 'depotids' in info and info['depotids'] and info['billingtype'] in BillingType.PaidList:  # 如果有仓库ID且为付费安装包
                        app_id_list.extend(list(info['appids'].values()))  # 将appID添加到列表中

        self.log.info(f'User {username}: {len(app_id_list)} paid app found!')  # 记录信息日志
        if not app_id_list:  # 如果appID列表为空
            self.user_info[username]['enable'] = False  # 禁用用户
            self.user_info[username]['status'] = result  # 更新用户状态
            logging.warning(f'User {username}: Does not have any app and has been disabled!')  # 记录警告日志
            return  # 返回

        self.log.debug(f'User {username}, paid app id list: ' + ','.join([str(i) for i in app_id_list]))  # 记录调试日志
        self.log.info(f'User {username}: Waiting to get app info!')  # 记录信息日志
        fresh_resp = self.retry(steam.get_product_info, app_id_list, retry_num=self.retry_num)  # 获取应用信息
        if not fresh_resp:  # 如果获取失败
            logging.error(f'User {username}: Failed to get app info!')  # 记录错误日志
            return  # 返回

        job_list = []  # 初始化任务列表
        flag = True  # 初始化标志变量
        for app_id in app_id_list:  # 遍历appID列表
            if self.update_app_id_list and int(app_id) not in self.update_app_id_list:  # 如果需要更新应用列表且appID不在列表中
                continue  # 跳过当前循环
            with lock:  # 使用互斥锁确保线程安全
                if int(app_id) in self.app_lock:  # 如果appID已经被锁定
                    continue  # 跳过当前循环
                self.log.debug(f'Lock app: {app_id}')  # 记录调试日志
                self.app_lock[int(app_id)] = set()  # 锁定appID
            app = fresh_resp['apps'][app_id]  # 获取应用信息
            if 'common' in app and app['common']['type'].lower() in ['game', 'dlc', 'application']:  # 如果应用类型为游戏、DLC或应用程序
                if 'depots' not in fresh_resp['apps'][app_id]:  # 如果没有仓库信息
                    continue  # 跳过当前循环
                for depot_id, depot in fresh_resp['apps'][app_id]['depots'].items():  # 遍历仓库信息
                    with lock:  # 使用互斥锁确保线程安全
                        self.app_lock[int(app_id)].add(depot_id)  # 锁定仓库ID
                    if 'manifests' in depot and 'public' in depot['manifests'] and int(
                            depot_id) in {*cdn.licensed_depot_ids, *cdn.licensed_app_ids}:  # 如果有清单信息且为公共清单且仓库ID为已授权的仓库ID或应用程序ID之一
                        manifest_gid = depot['manifests']['public']  # 获取公共清单的GUID
                        self.set_depot_info(depot_id, manifest_gid)  # 设置仓库信息
                        with lock:  # 使用互斥锁确保线程安全
                            if int(app_id) not in self.user_info[username]['app']:  # 如果用户的应用列表中不存在该应用
                                self.user_info[username]['app'].append(int(app_id))  # 添加应用到用户的应用列表中
                            if self.check_manifest_exist(depot_id, manifest_gid):  # 如果已经获取了该清单
                                self.log.info(f'Already got the manifest: {depot_id}_{manifest_gid}')  # 记录信息日志
                                continue  # 跳过当前循环
                        flag = False  # 更新标志变量
                        job = gevent.Greenlet(LogExceptions(self.async_task), cdn, app_id, depot_id, manifest_gid)  # 创建绿色线程
                        job.rawlink(
                            functools.partial(self.get_manifest_callback, username, app_id, depot_id, manifest_gid))  # 设置绿色线程的目标函数
                        job_list.append(job)  # 将绿色线程添加到任务列表中
                        gevent.idle()  # 等待绿色线程空闲
                for job in job_list:  # 遍历任务列表
                    job.start()  # 启动绿色线程
            with lock:  # 使用互斥锁确保线程安全
                if int(app_id) in self.app_lock and not self.app_lock[int(app_id)]:  # 如果appID已经被锁定且仓库ID已经被下载完
                    self.log.debug(f'Unlock app: {app_id}')  # 记录调试日志
                    self.app_lock.pop(int(app_id))  # 解锁appID
        with lock:  # 使用互斥锁确保线程安全
            if flag:  # 如果所有应用都已下载完
                self.user_info[username]['update'] = int(time.time())  # 更新上次更新时间
        gevent.joinall(job_list)  # 等待所有绿色线程结束


    def run(self, update=False):
        """
        运行函数，用于执行一系列操作

        参数：
        update(bool): 是否更新，默认为False

        返回值：
        无

        """
        if not self.account_info or self.init_only:
            # 如果没有账户信息或者仅初始化
            self.save()  # 保存当前状态
            self.account_info.dump()  # 保存账户信息
            return  # 返回

        if update and not self.update_user_list:
            # 如果需要更新并且没有更新用户列表
            self.update()  # 更新
            if not self.update_user_list:
                return  # 返回

        with Pool(self.pool_num) as pool:
            pool: ThreadPool
            result_list = []

            for username in self.account_info:
                if self.update_user_list and username not in self.update_user_list:
                    # 如果有更新用户列表且用户不在列表中
                    self.log.debug(f'User {username} has skipped the update!')  # 在日志中记录用户更新被跳过
                    continue  # 跳过该用户

                password, sentry_name = self.account_info[username]
                result_list.append(
                    pool.apply_async(LogExceptions(self.get_manifest), (username, password, sentry_name)))

            try:
                while pool._state == 'RUN':
                    # 当池子状态为运行时
                    if all([result.ready() for result in result_list]):
                        # 如果所有结果都准备好了
                        self.log.info('The program is finished and will exit in 10 seconds!')  # 在日志中记录程序将在10秒后退出
                        time.sleep(10)  # 等待10秒
                        break  # 跳出循环
                    self.save()  # 保存当前状态
                    time.sleep(1)  # 等待1秒

            except KeyboardInterrupt:
                # 捕捉键盘中断
                with lock:
                    pool.terminate()  # 终止池子
                os._exit(0)  # 退出进程

            finally:
                self.save()  # 保存当前状态


    def update(self):
        app_id_list = []
        for user, info in self.user_info.items():
            if info['enable']:
                if info['app']:
                    app_id_list.extend(info['app'])
        app_id_list = list(set(app_id_list))
        logging.debug(app_id_list)
        steam = MySteamClient(str(self.credential_location))
        self.log.info('Logging in to anonymous!')
        steam.anonymous_login()
        self.log.info('Waiting to get all app info!')
        app_info_dict = {}
        count = 0
        while app_id_list[count:count + 300]:
            fresh_resp = self.retry(steam.get_product_info, app_id_list[count:count + 300],
                                    retry_num=self.retry_num, timeout=60)
            count += 300
            if fresh_resp:
                for app_id, info in fresh_resp['apps'].items():
                    if depots := info.get('depots'):
                        app_info_dict[int(app_id)] = depots
                self.log.info(f'Acquired {len(app_info_dict)} app info!')
        update_app_set = set()
        for app_id, app_info in app_info_dict.items():
            for depot_id, depot in app_info.items():
                if depot_id.isdecimal():
                    if manifests := depot.get('manifests'):
                        if manifest := manifests.get('public'):
                            if depot_id in self.app_info and self.app_info[depot_id] != manifest:
                                update_app_set.add(app_id)
        update_app_user = {}
        update_user_set = set()
        for user, info in self.user_info.items():
            if info['enable'] and info['app']:
                for app_id in info['app']:
                    if int(app_id) in update_app_set:
                        if int(app_id) not in update_app_user:
                            update_app_user[int(app_id)] = []
                        update_app_user[int(app_id)].append(user)
                        update_user_set.add(user)
        self.log.debug(str(update_app_user))
        for user in self.account_info:
            if user not in self.user_info:
                update_user_set.add(user)
        self.update_user_list.extend(list(update_user_set))
        for app_id, user_list in update_app_user.items():
            self.log.info(f'{app_id}: {",".join(user_list)}')
        self.log.info(f'{len(update_app_user)} app and {len(self.update_user_list)} users need to update!')
        return self.update_user_list


if __name__ == '__main__':
    args = parser.parse_args()
    ManifestAutoUpdate(args.credential_location, level=args.level, pool_num=args.pool_num, retry_num=args.retry_num,
                       update_wait_time=args.update_wait_time, key=args.key, init_only=args.init_only,
                       cli=args.cli, app_id_list=args.app_id_list, user_list=args.user_list).run(update=args.update)
    if not args.no_push:
        if not args.init_only:
            push()
        push_data()
