require 'sinatra/base'
require 'digest/sha2'
require 'mysql2-cs-bind'
require 'rack-flash'
require 'json'
require 'rack-lineprof'
# require 'newrelic_rpm'

module Isucon4
  class App < Sinatra::Base
    use Rack::Session::Cookie, secret: ENV['ISU4_SESSION_SECRET'] || 'shirokane'
    use Rack::Flash
    # use Rack::Lineprof, profile: 'app.rb'
    set :public_folder, File.expand_path('../../public', __FILE__)

    # no js injection in the page
    # newrelic_ignore_enduser

    helpers do
      def config
        @config ||= {
          user_lock_threshold: (ENV['ISU4_USER_LOCK_THRESHOLD'] || 3).to_i,
          ip_ban_threshold: (ENV['ISU4_IP_BAN_THRESHOLD'] || 10).to_i,
        }
      end

      def db
        Thread.current[:isu4_db] ||= Mysql2::Client.new(
          host: ENV['ISU4_DB_HOST'] || 'localhost',
          port: ENV['ISU4_DB_PORT'] ? ENV['ISU4_DB_PORT'].to_i : nil,
          username: ENV['ISU4_DB_USER'] || 'root',
          password: ENV['ISU4_DB_PASSWORD'],
          database: ENV['ISU4_DB_NAME'] || 'isu4_qualifier',
          reconnect: true,
        )
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def count_user_failure(user_id)
        log = db.xquery('SELECT success_flag,failure_count FROM user_login_failure WHERE user_id = ?', user_id).first
        return [0, 0] unless log
        [log['success_flag'], log['failure_count']]
      end

      def count_ip_failure(ip)
        log = db.xquery('SELECT success_flag,failure_count FROM ip_login_failure WHERE ip = ?', ip).first
        return [0, 0] unless log
        [log['success_flag'], log['failure_count']]
      end

      def login_log(succeeded, login, user_id = nil)
        db.xquery("INSERT INTO login_log" \
                  " (`created_at`, `user_id`, `login`, `ip`, `succeeded`)" \
                  " VALUES (?,?,?,?,?)",
                 Time.now, user_id, login, request.ip, succeeded ? 1 : 0)

        login_log_failure(succeeded, request.ip, user_id)
      end

      def login_log_failure(succeeded, ip, user_id = nil)
        if succeeded
          to_user_success = 1
          to_ip_success = 1
          to_user_count = 0
          to_ip_count = 0
        else
          to_user_success, to_user_count = count_user_failure(user_id)
          to_ip_success, to_ip_count = count_ip_failure(ip)
          to_user_count += 1
          to_ip_count += 1
        end

        if user_id
          db.xquery("insert into user_login_failure(user_id, success_flag, failure_count) values(?, ?, ?) on duplicate key update success_flag = ?, failure_count = ?", user_id, to_user_success, to_user_count, to_user_success, to_user_count)
        end
        db.xquery("insert into ip_login_failure(ip, success_flag, failure_count) values(?, ?, ?) on duplicate key update success_flag = ?, failure_count = ?", ip, to_ip_success, to_ip_count, to_ip_success, to_ip_count)
      end

      def user_locked?(user)
        return nil unless user
        config[:user_lock_threshold] <= count_user_failure(user['id']).last
      end

      def ip_banned?
        config[:ip_ban_threshold] <= count_ip_failure(request.ip).last
      end

      def attempt_login(login, password)
        user = db.xquery('SELECT * FROM users WHERE login = ?', login).first

        if ip_banned?
          login_log(false, login, user ? user['id'] : nil)
          return [nil, :banned]
        end

        if user_locked?(user)
          login_log(false, login, user['id'])
          return [nil, :locked]
        end

        if user && calculate_password_hash(password, user['salt']) == user['password_hash']
          login_log(true, login, user['id'])
          [user, nil]
        elsif user
          login_log(false, login, user['id'])
          [nil, :wrong_password]
        else
          login_log(false, login)
          [nil, :wrong_login]
        end
      end

      def current_user
        return @current_user if @current_user
        return nil unless session[:user_id]

        @current_user = db.xquery('SELECT * FROM users WHERE id = ?', session[:user_id].to_i).first
        unless @current_user
          session[:user_id] = nil
          return nil
        end

        @current_user
      end

      def last_login
        return nil unless current_user

        db.xquery('SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2', current_user['id']).each.last
      end

      def banned_ips
        ips = []
        threshold = config[:ip_ban_threshold]

        [0, 1].each do |flag|
          db.xquery('SELECT * FROM ip_login_failure WHERE success_flag = ? AND failure_count >= ?', flag, threshold).each do |row|
            ips << row['ip']
          end
        end
        ips
      end

      def locked_users
        user_ids = []
        threshold = config[:user_lock_threshold]
        [0, 1].each do |flag|
          db.xquery('SELECT users.login FROM users INNER JOIN user_login_failure ON users.id = user_login_failure.user_id WHERE success_flag = ? AND user_login_failure.failure_count >= ?', flag, threshold).each do |row|
            user_ids << row['login']
          end
        end
        user_ids
      end
    end

    get '/' do
      erb :index, layout: :base
    end

    post '/login' do
      user, err = attempt_login(params[:login], params[:password])
      if user
        session[:user_id] = user['id']
        redirect '/mypage'
      else
        case err
        when :locked
          flash[:notice] = "This account is locked."
        when :banned
          flash[:notice] = "You're banned."
        else
          flash[:notice] = "Wrong username or password"
        end
        redirect '/'
      end
    end

    get '/mypage' do
      unless current_user
        flash[:notice] = "You must be logged in"
        redirect '/'
      end
      erb :mypage, layout: :base
    end

    get '/report' do
      content_type :json
      {
        banned_ips: banned_ips,
        locked_users: locked_users,
      }.to_json
    end

    get '/dump' do
      db.xquery('DELETE FROM user_login_failure')
      db.xquery('DELETE FROM ip_login_failure')

      db.xquery('SELECT * FROM login_log').each do |log|
        login_log_failure(log['succeeded'] == 1, log['ip'], log['user_id'])
      end

      content_type :json
      { a: 'b' }.to_json
    end
  end
end
