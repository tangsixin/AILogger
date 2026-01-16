import pandas as pd
import hashlib
import re

# 统一盐值，确保 SIP 和 IAM 关联一致
SALT = "Sec_AnHui_2024"


def get_hash(value):
    """提取纯净IP并生成唯一ID"""
    if pd.isna(value) or value == "": return "N/A"
    # 提取括号前的纯IP (处理 1.1.1.1(中国) 这种情况)
    clean_ip = str(value).split('(')[0].strip()
    return hashlib.sha256((clean_ip + SALT).encode()).hexdigest()[:12].upper()


def mask_raw_log(raw_text):
    """
    使用正则表达式替换原始日志字符串中的 SrcIP 和 DstIP
    """
    if pd.isna(raw_text): return raw_text

    # 匹配 SrcIP=xxx.xxx.xxx.xxx 或 DstIP=xxx.xxx.xxx.xxx
    # 或者通用的 IP 格式
    def replace_ip(match):
        prefix = match.group(1)  # SrcIP= 或 DstIP=
        ip = match.group(2)
        return f"{prefix}{get_hash(ip)}"

    # 替换 SrcIP=...
    raw_text = re.sub(r'(SrcIP=)([0-9.]+)', replace_ip, raw_text)
    # 替换 DstIP=...
    raw_text = re.sub(r'(DstIP=)([0-9.]+)', replace_ip, raw_text)

    return raw_text


def process_sip(input_file):
    print(f"开始脱敏 SIP 日志: {input_file}")
    df = pd.read_excel(input_file)

    # 1. 处理外层显性字段
    ip_cols = ['源地址', '目的地址', '设备地址']
    for col in ip_cols:
        if col in df.columns:
            df[f'{col}_ID'] = df[col].apply(get_hash)
            # 仅保留网段供汇报展示
            df[f'{col}_展示'] = df[col].apply(lambda x: ".".join(str(x).split('(')[0].split('.')[:3]) + ".*")
            df.drop(columns=[col], inplace=True)

    # 2. 处理“原始日志”内部的嵌套信息 (核心难点)
    if '原始日志' in df.columns:
        print("正在深度解析原始日志字符串...")
        df['原始日志'] = df['原始日志'].apply(mask_raw_log)

    output = "sip_masked_final.xlsx"
    df.to_excel(output, index=False)
    print(f"SIP 脱敏完成，结果：{output}\n")


if __name__ == "__main__":
    process_sip("sip.xls")