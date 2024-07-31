include /home/isucon/env.sh

# 問題によって変わる変数
USER:=isucon
BIN_NAME:=app
BUILD_DIR:=/home/isucon/private_isu/webapp/golang
SERVICE_NAME:=isu-go

DB_PATH:=/etc/mysql
NGINX_PATH:=/etc/nginx

DB_SLOW_LOG:=/var/log/mysql/mysql-slow.log
NGINX_LOG:=/var/log/nginx/access.log

NOTIFY_SLACK_TMPFILE:=tmp/notify-slack.txt

# メインで使うコマンド ------------------------

# サーバーの環境構築　ツールのインストール、gitまわりのセットアップ
.PHONY: setup
setup: install-tools dir-setup git-setup

# 設定ファイルなどを取得してgit管理下に配置する
.PHONY: get-conf
get-conf: get-db-conf get-nginx-conf

# リポジトリ内の設定ファイルをそれぞれ配置する
.PHONY: deploy-conf
deploy-conf: deploy-db-conf deploy-nginx-conf

# ベンチマークを走らせる直前に実行する
.PHONY: bench
bench: build rm-logs deploy-conf restart

# slow queryを確認する
.PHONY: slow-query
slow-query: 
	sudo pt-query-digest $(DB_SLOW_LOG)

# notify_slackでslow-queryを通知する
.PHONY: notify-slack-slow-query
notify-slack-slow-query: 
	$(eval when := $(shell date "+%Y-%m-%d-%H:%M:%S"))
	make refresh-notify-slack-tmp
	make slow-query >> $(NOTIFY_SLACK_TMPFILE)
	cat $(NOTIFY_SLACK_TMPFILE) | notify_slack -c tool-config/slow-query/notify-slack.toml -snippet -filename=$(when).txt

# alpでアクセスログを確認する
.PHONY: alp
alp:
	sudo alp ltsv --file=$(NGINX_LOG) --config=tool-config/alp/config.yml

# notify_slackでalpの結果を通知する
.PHONY: notify-slack-alp
notify-slack-alp:
	$(eval when := $(shell date "+%Y-%m-%d-%H:%M:%S"))
	make refresh-notify-slack-tmp
	make alp >> $(NOTIFY_SLACK_TMPFILE)
	cat $(NOTIFY_SLACK_TMPFILE) | notify_slack -c tool-config/alp/notify-slack.toml -snippet -filename=$(when).txt

# pprofで記録する
.PHONY: pprof-record
pprof-record: 
	go tool pprof http://localhost:6060/debug/pprof/profile

# pprofで確認する
.PHONY: pprof-check
pprof-check: 
	$(eval latest := $(shell ls -rt ~/pprof/ | tail -n 1))
	go tool pprof -http=localhost:8090 ~/pprof/$(latest)

# DBに接続する
.PHONY: access-db
access-db: 
	mysql -h $(MYSQL_HOST) -P $(MYSQL_PORT) -u $(MYSQL_USER) -p $(MYSQL_PASS) $(MYSQL_DBNAME)

# 主要コマンドの構成要素 ------------------------

.PHONY: install-tools
install-tools:
	sudo apt update
	sudo apt upgrade
	sudo apt install -y percona-toolkit dstat git unzip snapd graphviz tree

	# alpのインストール
	wget https://github.com/tkuchiki/alp/releases/download/v1.0.9/alp_linux_amd64.zip
	unzip alp_linux_amd64.zip
	sudo install alp /usr/local/bin/alp
	rm alp_linux_amd64.zip alp

	# notify_slackのインストール
	wget https://github.com/catatsuy/notify_slack/releases/download/v0.5.1/notify_slack-linux-amd64.tar.gz
	tar -xvf notify_slack-linux-amd64.tar.gz
	sudo install notify_slack /usr/local/bin/notify_slack
	rm notify_slack-linux-amd64.tar.gz notify_slack LICENSE CHANGELOG.md README.md

.PHONY: dir-setup
dir-setup:
	mkdir -p tool-config/alp tool-config/slow-query etc/nginx etc/mysql

.PHONY: git-setup
git-setup:
	# git用の設定は適宜変更して良い
	git config --global user.email "yuhi120101@gmail.com"
	git config --global user.name "Yuhi-Sato"

	# deploykeyの作成
	ssh-keygen -t ed25519

.PHONY: get-db-conf
get-db-conf:
	sudo cp -R $(DB_PATH)/* etc/mysql
	sudo chown $(USER) -R etc/mysql

.PHONY: get-nginx-conf
get-nginx-conf:
	sudo cp -R $(NGINX_PATH)/* etc/nginx
	sudo chown $(USER) -R etc/nginx

.PHONY: deploy-db-conf
deploy-db-conf: 
	sudo cp -R etc/mysql/* $(DB_PATH)

.PHONY: deploy-nginx-conf
deploy-nginx-conf: 
	sudo cp -R etc/nginx/* $(NGINX_PATH)

.PHONY: build
build:
	cd $(BUILD_DIR); \
	go build -o $(BIN_NAME)

.PHONY: restart
restart:
	sudo systemctl daemon-reload
	sudo systemctl restart $(SERVICE_NAME)
	sudo systemctl restart mysql
	sudo systemctl restart nginx

.PHONY: rm-logs
rm-logs:
	sudo rm -f $(NGINX_LOG)
	sudo rm -f $(DB_SLOW_LOG)

.PHONY: refresh-notify-slack-tmp
refresh-notify-slack-tmp:
	rm -f $(NOTIFY_SLACK_TMPFILE)
	mkdir -p tmp
	touch $(NOTIFY_SLACK_TMPFILE)

.PHONY: watch-service-log
watch-service-log:
	sudo journalctl -u $(SERVICE_NAME) -n10 -f

 
