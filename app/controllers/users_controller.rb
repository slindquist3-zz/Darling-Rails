class UsersController < ApplicationController
  # skip_before_action :verify_authenticity_token

  def index
    @users = User.all
    render json: @users
  end

  # GET /users/1
  def show
    render json: @user
  end

  def create
    @user = User.new(user_params)

    if @user.save
      @cart = Cart.create(user_id: @user.id)
      jwt = Auth.issue({auth: @user.id})
      render json: {jwt: jwt, cart_id: @cart.id}

    else
      "Error!"
    end
  end

  # PATCH/PUT /users/1
  def update
    # byebug
    @user = User.find(params[:id])
    if @user.update(user_params)
      render json: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # DELETE /users/1
  def destroy
    @user = User.find(params[:id])
    @user.destroy
    #should this destroy that match as well?
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Only allow a trusted parameter "white list" through.
    def user_params
      params.require(:user).permit(:name, :email, :password)
    end


end
