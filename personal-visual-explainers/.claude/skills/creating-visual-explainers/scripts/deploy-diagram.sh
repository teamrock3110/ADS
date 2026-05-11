#!/bin/bash
set -e

HTML_FILE="${1:?使い方: deploy-diagram.sh <HTMLファイル> [スラッグ]}"
SLUG="${2:-}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if ! command -v node &>/dev/null; then
    echo -e "${RED}エラー: Node.js がインストールされていません${NC}" >&2
    echo "Node.js をインストールしてから、もう一度試してください。" >&2
    exit 1
fi

if [ ! -f "$HTML_FILE" ]; then
    echo -e "${RED}エラー: $HTML_FILE が見つかりません${NC}" >&2
    echo "先に図解を生成してください。" >&2
    exit 1
fi

if [ -n "$SLUG" ]; then
    DOMAIN="diagram-${SLUG}.surge.sh"
else
    DOMAIN="diagram-$(date +%y%m%d%H%M).surge.sh"
fi

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

cp "$HTML_FILE" "$TEMP_DIR/index.html"
printf "User-agent: *\nDisallow: /\n" > "$TEMP_DIR/robots.txt"

echo -e "${YELLOW}公開中...${NC}"
npx --yes surge "$TEMP_DIR" --domain "$DOMAIN"

touch deploy-history.log
echo "$(date '+%Y-%m-%d %H:%M:%S') | https://${DOMAIN}" >> deploy-history.log

echo ""
echo -e "${GREEN}完了！${NC}"
echo "URL: https://${DOMAIN}"

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "https://${DOMAIN}" | pbcopy
    echo -e "${GREEN}URLをクリップボードにコピーしました${NC}"
    open "https://${DOMAIN}"
elif command -v clip.exe &>/dev/null; then
    echo -n "https://${DOMAIN}" | clip.exe
    echo -e "${GREEN}URLをクリップボードにコピーしました${NC}"
    start "https://${DOMAIN}" 2>/dev/null || true
elif command -v xdg-open &>/dev/null; then
    xdg-open "https://${DOMAIN}"
fi

echo -e "${YELLOW}削除するとき: npx surge teardown ${DOMAIN}${NC}"
