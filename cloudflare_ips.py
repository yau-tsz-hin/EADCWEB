import requests

def fetch_cloudflare_ips():
    """從 Cloudflare 官方網站抓取 IP 範圍"""
    ipv4_url = "https://www.cloudflare.com/ips-v4"
    ipv6_url = "https://www.cloudflare.com/ips-v6"

    try:
        # 抓取 IPv4 和 IPv6 範圍
        ipv4_ranges = requests.get(ipv4_url).text.splitlines()
        ipv6_ranges = requests.get(ipv6_url).text.splitlines()

        return ipv4_ranges, ipv6_ranges
    except requests.RequestException as e:
        print(f"無法抓取 Cloudflare IP 範圍: {e}")
        return [], []

def save_ips_to_file(ipv4, ipv6, file_path="cloudflare_ips.txt"):
    """將 IP 範圍保存到檔案"""
    if not ipv4 and not ipv6:
        print("抓取的 IP 範圍為空，未保存！")
        return

    try:
        with open(file_path, "w") as file:
            file.write("# Cloudflare IP 範圍\n")
            file.write("# IPv4 範圍\n")
            file.write("192.168.0.0/24\n")
            file.writelines(f"{ip}\n" for ip in ipv4)
            file.write("\n# IPv6 範圍\n")
            file.writelines(f"{ip}\n" for ip in ipv6)
        print(f"IP 範圍已成功保存到 {file_path}")
    except IOError as e:
        print(f"無法保存到檔案 {file_path}: {e}")

if __name__ == "__main__":
    # 抓取並保存
    ipv4, ipv6 = fetch_cloudflare_ips()
    save_ips_to_file(ipv4, ipv6)
