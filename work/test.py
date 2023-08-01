import os
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import re
from PIL import Image, ImageOps

# Image save folder
IMG_FOLDER = "imgs"

# URL template with package name placeholder
URL_TEMPLATE = "https://apkcombo.com/find-it-out-scavenger-hunt/{}"

# Image constraints
MAX_SIZE_KB = 100
IMAGE_SIZE_LANDSCAPE = (800, 450)
IMAGE_SIZE_PORTRAIT = (450, 800)


def get_game_info(package_name):
    url = URL_TEMPLATE.format(package_name)
    response = requests.get(url, allow_redirects=True)
    soup = BeautifulSoup(response.text, 'html.parser')

    # 从标题标签获取游戏名称
    game_title = soup.find("h1").find("a").get_text(strip=True)

    # 获取版本
    version = soup.find("div", class_="version").get_text(strip=True)

    # 获取作者
    author = soup.find("div", class_="author").find("a").get_text(strip=True)

    # 获取简要描述
    short_description = soup.find("h2", class_="short-description").get_text(strip=True)

    # 获取图片链接
    gallery_div = soup.find("div", id="gallery-screenshots")
    image_urls = [img['data-src'] for img in gallery_div.find_all("img")]

    return {
        "游戏名称": game_title,
        "版本": version,
        "作者": author,
        "简要描述": short_description,
        "图片链接": image_urls
    }


def download_images(image_urls):
    """下载图片到指定文件夹，并显示进度条

    :param image_urls: 图片URL数组
    """

    if not os.path.exists(IMG_FOLDER):
        os.makedirs(IMG_FOLDER)

    # 使用tqdm包装image_urls迭代器以显示进度条
    for idx, img_url in enumerate(tqdm(image_urls, desc="下载进度", unit="image")):
        # 使用正则表达式从URL中获取宽度和高度
        match = re.search(r'w(\d+)-h(\d+)', img_url)
        if match:
            width = int(match.group(1))
            height = int(match.group(2))

            # 判断是竖屏还是横屏，并相应地调整宽高
            if height > width:
                new_width, new_height = IMAGE_SIZE_PORTRAIT
            else:
                new_width, new_height = IMAGE_SIZE_LANDSCAPE

            # 更新URL中的宽度和高度
            new_img_url = img_url.replace(f"w{width}", f"w{new_width}").replace(f"h{height}", f"h{new_height}")

            response = requests.get(new_img_url)
            with open(f"{IMG_FOLDER}/image_{idx}.webp", 'wb') as file:
                file.write(response.content)

    # Resize images
    for idx, img_url in enumerate(image_urls):
        image_path = os.path.join(IMG_FOLDER, f"image_{idx}.webp")
        resize_image(image_path, IMAGE_SIZE_PORTRAIT if is_portrait(image_path) else IMAGE_SIZE_LANDSCAPE)
        os.remove(image_path)  # 删除原始的 .webp 文件


def is_portrait(image_path):
    img = Image.open(image_path)
    width, height = img.size
    return height > width


def resize_image(image_path, image_size):
    img = Image.open(image_path).convert('RGB')
    img = ImageOps.exif_transpose(img)  # 如果图片有方向元数据, 用此方法矫正方向
    img = img.resize(image_size, Image.LANCZOS)  # 使用 LANCZOS 替代 ANTIALIAS

    output_filename = os.path.splitext(os.path.basename(image_path))[0] + '.jpg'
    output_path = os.path.join(IMG_FOLDER, output_filename)  # 修改保存路径

    quality = 90
    while quality > 0:
        img.save(output_path, 'JPEG', quality=quality)
        if os.path.getsize(output_path) < MAX_SIZE_KB * 1024:
            break
        quality -= 10


if __name__ == '__main__':
    package_name = "com.levelinfinite.sgameGlobal"
    game_info = get_game_info(package_name)
    print(f"游戏名称: {game_info['游戏名称']}")
    print(f"版本: {game_info['版本']}")
    print(f"作者: {game_info['作者']}")
    print(f"简要描述: {game_info['简要描述']}")
    print("正在下载图片...")
    download_images(game_info['图片链接'])
    print("图片下载完成")