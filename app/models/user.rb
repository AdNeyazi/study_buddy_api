class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: JwtDenylist

  def generate_jwt
    JWT.encode(
      {
        id: id,
        email: email,
        jti: SecureRandom.uuid,
        exp: 1.day.from_now.to_i
      },
      Rails.application.credentials.devise_jwt_secret_key || "your_devise_jwt_secret_key"
    )
  end
end
