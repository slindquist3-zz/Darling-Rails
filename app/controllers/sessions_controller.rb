class SessionsController < ApplicationController

  # skip_before_action :authenticate

  def create
    user = User.find_by(email: user_params[:email])
    if user.authenticate(user_params[:password])
      jwt = Auth.issue({auth: user.id})
      render json: {jwt: jwt}
    else
    end
  end

  private
    def user_params
      params.require(:user).permit(:email, :password)
    end

end
