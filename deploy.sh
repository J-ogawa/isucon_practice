#!/bin/sh

ssh_host="ec2-user@52.197.135.194"
cwd=`dirname "${0}"`
expr "${0}" : "/.*" > /dev/null || cwd=`(cd "${cwd}" && pwd)`

rsync -av --exclude=".git/*" --exclude="ruby/.bundle/*" --exclude="ruby/vendor/bundle/**/*" -e ssh "${cwd}/" "${ssh_host}:/home/ec2-user/"

ssh -t -t $ssh_host <<-EOS
sudo sysctl -p
echo "======================================================"
ulimit -a
echo "======================================================"
sudo service mysqld restart
sudo service nginx restart
sudo supervisorctl restart isucon_ruby
sudo su - isucon
cd /home/isucon/webapp/ruby
bundle install
exit
exit
EOS