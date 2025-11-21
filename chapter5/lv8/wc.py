import sys
import re
from collections import Counter

def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <filename>" % sys.argv[0])
        sys.exit(1)

    filename = sys.argv[1]

    try:
        with open(filename, "r") as f:
            text = f.read()
    except Exception as e:
        print("Error reading file: %s" % e)
        sys.exit(1)

    
    # text = text.lower() # 注释此行则大小写不敏感

    # 提取单词
    words = re.findall(r"[A-Za-z0-9]+", text)

    counter = Counter(words)

    # 输出：按出现次数从多到少排序
    for word, count in counter.most_common():
        print("%s: %d" % (word, count))


if __name__ == "__main__":
    main()
