class CreateProducts < ActiveRecord::Migration[5.0]
  def change
    create_table :products do |t|
      t.string :name
      t.string :thumbnail
      t.string :price
      t.integer :cart_id

      t.timestamps
    end
  end
end
