import os
import sys
import time
import socket
import platform
import requests
import yaml
import uuid
import re
import gzip
import zstd
import logging
import urllib.request
import psutil
import subprocess
from datetime import datetime
import concurrent.futures  # 新增导入
from requests.adapters import HTTPAdapter  # 新增
from urllib3.util.retry import Retry  # 新增

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler()]
)

# 本地存储 host_id 的文件路径
LOCAL_ID_FILE = os.getenv('HOST_ID_FILE_PATH', os.path.expanduser("~/.host_id"))
# 缓存 IP 地址和最后更新时间
cached_ip = None
last_update_time = 0
# 客户端版本
CLIENT_VERSION = "v0.1.5"
# 客户端启动时间
START_TIME = datetime.now()  # 确保初始化为 datetime 对象

# 检测是否运行在容器内
def is_in_container():
    """检测是否运行在容器内"""
    # 检查/.dockerenv文件是否存在
    if os.path.exists('/.dockerenv'):
        return True
    
    # 检查cgroup信息
    try:
        with open('/proc/1/cgroup', 'r') as f:
            content = f.read()
            if 'docker' in content or 'kubepods' in content or 'container' in content:
                return True
    except:
        pass
    
    return False

# 获取或生成 host_id
def get_host_id():
    host_id = os.getenv('HOST_ID')
    if host_id:
        return host_id
    if os.path.exists(LOCAL_ID_FILE):
        with open(LOCAL_ID_FILE, 'r') as f:
            return f.read().strip()
    host_id = str(uuid.uuid4())
    os.makedirs(os.path.dirname(LOCAL_ID_FILE), exist_ok=True)
    with open(LOCAL_ID_FILE, 'w') as f:
        f.write(host_id)
    return host_id

def get_os_info():
    """获取操作系统详细信息"""
    try:
        # 如果在容器中，优先尝试从挂载的宿主机文件系统读取
        if is_in_container():
            host_paths = [
                '/host/etc/os-release',
                '/host/etc/redhat-release',
                '/host/etc/lsb-release',
            ]
            
            for host_path in host_paths:
                if os.path.exists(host_path):
                    try:
                        with open(host_path, 'r') as f:
                            if host_path.endswith('os-release'):
                                lines = f.readlines()
                                os_info = {}
                                for line in lines:
                                    if '=' in line:
                                        key, value = line.strip().split('=', 1)
                                        os_info[key] = value.strip('"')
                                name = os_info.get('PRETTY_NAME', os_info.get('NAME', 'Unknown'))
                                version = os_info.get('VERSION_ID', '')
                                return f"{name} {version}".strip()
                            else:
                                content = f.read().strip()
                                if 'redhat' in host_path:
                                    return f"CentOS/RedHat {content}"
                                elif 'lsb' in host_path:
                                    return f"Ubuntu/Debian {content}"
                    except Exception as e:
                        logging.debug(f"从挂载路径 {host_path} 读取失败: {e}")
        
        # 通用方法：读取本地文件系统信息
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
            
            os_info = {}
            for line in lines:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os_info[key] = value.strip('"')
            
            name = os_info.get('PRETTY_NAME', os_info.get('NAME', 'Unknown'))
            version = os_info.get('VERSION_ID', '')
            
            return f"{name} {version}".strip()
        
        # 备用方案：检查特定发行版文件
        distro_files = {
            '/etc/redhat-release': 'RedHat/CentOS',
            '/etc/lsb-release': 'Ubuntu/Debian',
            '/etc/debian_version': 'Debian',
        }
        
        for file_path, distro_name in distro_files.items():
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                    return f"{distro_name} {content}"
        
        return platform.platform()
    except Exception as e:
        logging.warning(f"获取OS信息失败: {e}")
        return platform.platform()

def get_cpu_info():
    """获取CPU详细信息"""
    try:
        # 如果在容器中，优先尝试从挂载的宿主机文件系统读取
        if is_in_container() and os.path.exists('/host/proc/cpuinfo'):
            try:
                with open('/host/proc/cpuinfo', 'r') as f:
                    content = f.read()
                
                model_match = re.search(r'model name\s*:\s*(.+)', content)
                if model_match:
                    return model_match.group(1).strip()
            except Exception as e:
                logging.debug(f"从挂载的 /host/proc/cpuinfo 读取失败: {e}")
        
        # 通用方法：读取本地CPU信息
        if os.path.exists('/proc/cpuinfo'):
            with open('/proc/cpuinfo', 'r') as f:
                content = f.read()
            
            model_match = re.search(r'model name\s*:\s*(.+)', content)
            if model_match:
                return model_match.group(1).strip()
        
        # 尝试使用lscpu命令
        try:
            result = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                model_match = re.search(r'Model name:\s*(.+)', result.stdout)
                if model_match:
                    return model_match.group(1).strip()
                
                arch_match = re.search(r'Architecture:\s*(.+)', result.stdout)
                if arch_match:
                    return f"CPU Architecture: {arch_match.group(1).strip()}"
        except:
            pass
            
    except Exception as e:
        logging.warning(f"获取CPU信息失败: {e}")
    
    return platform.processor()


def get_disk_info():
    """获取磁盘信息，适配容器和宿主机环境"""
    disk_total = 0
    seen_devices = set()
    
    for part in psutil.disk_partitions():
        # 跳过特殊文件系统
        if part.fstype in ['tmpfs', 'devtmpfs', 'squashfs', 'overlay']:
            continue
            
        try:
            # 避免重复计算同一设备
            if part.device in seen_devices:
                continue
                
            disk_usage = psutil.disk_usage(part.mountpoint)
            disk_total += disk_usage.total
            seen_devices.add(part.device)
        except OSError as e:
            logging.warning(f"无法获取挂载点 {part.mountpoint} 的磁盘信息: {e}")
            continue
            
    return disk_total / (1024**3)  # 转换为 GB

# 获取主机信息
def get_host_info():
    hostname = socket.gethostname()
    ip = get_host_ip()
    public_ip = getIp()
    #os_version = platform.platform()
    os_version = get_os_info()
    # 计算磁盘总大小
    disk_total = get_disk_info()
    os_details = {
        'system': platform.system(), # 操作系统名称
        'release': platform.release(), # 操作系统版本
        'version': platform.version(), # 操作系统详细版本
        'machine': platform.machine(), # 机器类型
        'processor': get_cpu_info(), # 处理器类型
        'python_version': platform.python_version(), # Python 版本
        'cpu_count': psutil.cpu_count(), # CPU 核心数
        'memory_total': psutil.virtual_memory().total / (1024**3),  # 总内存大小，单位 GB
        'disk_total': disk_total,  # 总磁盘大小，单位 GB
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat() # 系统启动时间
    }
    logging.info(f"主机信息: {os_details}")
    return hostname, ip, public_ip, os_version, os_details

def getIp(cache_duration=600):
    global cached_ip, last_update_time
    # 检查环境变量是否指定了 PUBLIC_IP
    env_public_ip = os.getenv('PUBLIC_IP')
    if env_public_ip:
        logging.info(f"使用环境变量指定的公网IP: {env_public_ip}")
        return env_public_ip
    
    current_time = time.time()
    if cached_ip and (current_time - last_update_time < cache_duration):
        return cached_ip
    try:
        with urllib.request.urlopen('https://4.ipw.cn', timeout=5) as response:
            html = response.read()
            cached_ip = html.decode('utf-8').strip()
            last_update_time = current_time
            logging.info(f"成功获取公网IP: {cached_ip}")
            return cached_ip
    except Exception as e:
        logging.warning(f"获取公网IP地址时出错: {e}")
        # 如果获取失败，返回 'unknown' 作为默认值
        return cached_ip if cached_ip else 'unknown'

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# 读取 YAML 配置文件
def read_config(config_path='./conf/config.yaml'):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logging.error(f"Error reading configuration file: {e}")
        sys.exit(1)

# 注册主机到服务端
def register_host(host_id, hostname, ip, public_ip, os_version, os_details, server_url, auth_token, region):
    registration_data = {
        'host_id': host_id,
        'region': region,
        'hostname': hostname,
        'ip': ip,
        'public_ip': public_ip,
        'os_version': os_version,
        'os_details': os_details,
        'client_version': CLIENT_VERSION
    }
    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': auth_token
    }
    try:
        response = requests.post(f"{server_url}/register", json=registration_data, headers=headers)
        response.raise_for_status()
        #logging.info(f"Host registered successfully: {response.json()}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to register host: {e}")
        logging.error(f"Request headers: {headers}")
        logging.error(f"Request URL: {server_url}/register")

# 从配置中抓取 Prometheus 指标数据并添加标签
def scrape_targets(scrape_configs, custom_labels, host_id, os_details):
    global START_TIME  # 声明 START_TIME 为全局变量
    metrics_data = ""
    current_timestamp = int(time.time())
    # 确保 START_TIME 是 datetime 对象
    if not isinstance(START_TIME, datetime):
        logging.warning(f"START_TIME is not a datetime object: {START_TIME}, resetting to current time")
        START_TIME = datetime.now()
    # 添加客户端信息指标
    labels = f'host_id="{host_id}"'
    for key, val in custom_labels.items():
        labels += f',{key}="{val}"'
    metrics_data += f'client_info{{version="{CLIENT_VERSION}",{labels}}} 1 {current_timestamp}\n'
    metrics_data += f'client_os{{system="{os_details["system"]}",release="{os_details["release"]}",version="{os_details["version"]}",machine="{os_details["machine"]}",processor="{os_details["processor"]}",python_version="{os_details["python_version"]}",{labels}}} 1 {current_timestamp}\n'
    metrics_data += f'client_hardware{{cpu_count="{os_details["cpu_count"]}",memory_total="{os_details["memory_total"]:.2f}",disk_total="{os_details["disk_total"]:.2f}",{labels}}} 1 {current_timestamp}\n'
    uptime_seconds = int((datetime.now() - START_TIME).total_seconds())
    metrics_data += f'client_uptime{{seconds="{uptime_seconds}",{labels}}} {uptime_seconds} {current_timestamp}\n'
    cpu_percent = psutil.cpu_percent(interval=1)
    metrics_data += f'client_cpu_usage{{percent="{cpu_percent}",{labels}}} {cpu_percent} {current_timestamp}\n'
    memory = psutil.virtual_memory()
    metrics_data += f'client_memory_usage{{percent="{memory.percent}",used="{memory.used / (1024**3):.2f}",free="{memory.free / (1024**3):.2f}",{labels}}} {memory.percent} {current_timestamp}\n'
    process_count = len(list(psutil.process_iter()))
    metrics_data += f'client_process_count{{count="{process_count}",{labels}}} {process_count} {current_timestamp}\n'

    current_timestamp = int(time.time())
    # 并发 scrape
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_target = {}
        for config in scrape_configs:
            job_name = config['job_name']
            for target in config['static_configs'][0]['targets']:
                future = executor.submit(requests.get, f"http://{target}/metrics", timeout=5)  # 缩短 timeout
                future_to_target[future] = (job_name, target)
        for future in concurrent.futures.as_completed(future_to_target):
            job_name, target = future_to_target[future]
            try:
                response = future.result()
                response.raise_for_status()
                labels = f'job="{job_name}",instance="{target}"'
                for key, val in custom_labels.items():
                    labels += f',{key}="{val}"'
                metrics_data += f'up{{{labels}}} 1 {current_timestamp}\n'
                lines = response.text.split('\n')
                for line in lines:
                    if line and not line.startswith('#'):
                        match = re.match(r'(\w+)(?:\{([^}]*)\})?\s+([\d\.\-eE\+]+)', line)
                        if not match:
                            logging.warning(f"Skipping invalid metric line: {line}")
                            continue
                        metric_name, existing_labels, value = match.groups()
                        metric_name = metric_name.strip()
                        value = value.strip()
                        existing_labels = existing_labels or ""
                        new_labels = f'{existing_labels},{labels}' if existing_labels else labels
                        metrics_data += f'{metric_name}{{{new_labels}}} {value} {current_timestamp}\n'
                    else:
                        metrics_data += line + '\n'
                #logging.info(f"Successfully scraped {len(response.text)} bytes from {target} for job {job_name}")
                #logging.info(f"Data sample (first 200 chars): {metrics_data[:200]}")
            except Exception as e:
                logging.error(f"Error scraping {target} for job {job_name}: {e}")
                labels = f'job="{job_name}",instance="{target}"'
                for key, val in custom_labels.items():
                    labels += f',{key}="{val}"'
                metrics_data += f'up{{{labels}}} 0 {current_timestamp}\n'
    logging.debug(f"Generated metrics:\n{metrics_data}")
    return metrics_data

# 将抓取到的指标数据发送到服务端
def send_metrics_to_server(metrics_data, host_id, victoria_metrics_url, auth_token, compression):
    session = create_retry_session()
    headers = {
        "X-Hostid": host_id,
        "Content-Type": "text/plain",
        "X-Auth-Token": auth_token
    }
    max_retries = 3
    for attempt in range(max_retries):
        try:
            data = metrics_data.encode('utf-8')
            if compression == 'gzip':
                headers['Content-Encoding'] = 'gzip'
                data = gzip.compress(data)
                logging.debug(f"Applied gzip compression, size: {len(data)} bytes")
            elif compression == 'zstd':
                headers['Content-Encoding'] = 'zstd'
                data = zstd.compress(data)
                logging.debug(f"Applied zstd compression, size: {len(data)} bytes")
            else:
                logging.debug(f"No compression applied, size: {len(data)} bytes")
            response = session.post(victoria_metrics_url, data=data, headers=headers, timeout=10)
            response.raise_for_status()
            #logging.info(f"Metrics sent successfully. Response: {response.text}")
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400 and 'Host not registered' in response.text:
                logging.warning(f"Host not registered on server. Attempting re-registration (attempt {attempt+1}/{max_retries})")
                # 重新获取主机信息（以防变化）
                hostname, ip, public_ip, os_version, os_details = get_host_info()
                # 调用注册（region 从 config 获取）
                register_host(host_id, hostname, ip, public_ip, os_version, os_details, victoria_metrics_url.rsplit('/report', 1)[0], auth_token)
            else:
                raise
        except requests.exceptions.RequestException as e:
            # 用于在发生异常时重试
            logging.error(f"Failed to send metrics (attempt {attempt+1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                raise  # 最终失败
            time.sleep(2 ** attempt)

# 创建一个带有重试机制的会话
def create_retry_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def main():
    config = read_config()
    victoria_metrics_url = config['victoria_metrics_url']
    report_interval = config['report_interval']
    scrape_configs = config['scrape_configs']
    auth_token = config.get('auth_token', '')
    custom_labels = config.get('labels', {})
    region = custom_labels.get('region', '')
    if 'project' in config and 'project' not in custom_labels:
        custom_labels['project'] = config['project']
    compression = config.get('compression', 'none').lower()  # 读取压缩方式，默认为 none
    if compression not in ['none', 'gzip', 'zstd']:
        logging.error(f"Invalid compression method: {compression}. Use 'none', 'gzip', or 'zstd'.")
        sys.exit(1)
    host_id = get_host_id()
    hostname, ip, public_ip, os_version, os_details = get_host_info()
    register_host(host_id, hostname, ip, public_ip, os_version, os_details, victoria_metrics_url.rsplit('/report', 1)[0], auth_token,region)
    while True:
        start_cycle = time.time()
        metrics_data = scrape_targets(scrape_configs, custom_labels, host_id, os_details)
        send_metrics_to_server(metrics_data, host_id, victoria_metrics_url, auth_token, compression)
        cycle_time = time.time() - start_cycle
        if cycle_time < report_interval:
            time.sleep(report_interval - cycle_time)
        else:
            logging.warning(f"Cycle overran by {cycle_time - report_interval}s")

if __name__ == "__main__":
    main()