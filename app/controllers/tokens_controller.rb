class TokensController < ApplicationController
  
  skip_before_filter :verify_authenticity_token
  
  def basic
    email = params[:email]
    password = params[:password]
    
    if request.format != :json
      render :status => 406, :json => {:message=>"The request must be json"}
      return
    end
    
    if email.nil? or password.nil?
      render :status => 400, :json => {:message => "the request must contain the user email and password"}
      return
    end
    
    @user = User.find_by_email(email.downcase)
    
    if @user.nil?
      render :status => 401, :json => {:message => "Invalid email or password"}
      return
    end
    
    @user.ensure_authentication_token!

    if not @user.valid_password?(password)
      render :status => 401, :json=>{:message=>"Invalid email or password"}
    else
      render :status => 200, :json => {:token => @user.authentication_token}
    end
  end
  
  def google
    # Use Google's Token Verification scheme to extract the user's email address
    token = params[:token]
    uri = URI.parse("https://www.googleapis.com")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    path = "/oauth2/v1/tokeninfo?access_token=#{token}"
    resp, data = http.get(path)
    data = JSON.parse(data)
    if resp.code == "200"
      # Find a user
      @user = User.where(:email => data["email"]).first
    else
      #Create a user with the data we just got back
    end
  end
  
  
end
