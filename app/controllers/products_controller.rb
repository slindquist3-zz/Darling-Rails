class ProductsController < ApplicationController

  def index
    @products = Product.all
    render json: @products
  end

  def show
    @product = Product.find(params[:id])
    render json: @product
  end

  def create
    @product = Product.create(product_params)
    render json: @product.cart, serializer: CartSerializer
  end

  private
  def product_params
    params.require(:product).permit(:name, :price, :thumbnail, :cart_id)
  end

  def destroy
    @product = Product.find(params[:id])
    @product.destroy
    render json: @products
  end

end
