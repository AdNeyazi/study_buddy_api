module JwtAuthenticatable
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_user_from_token!
  end

  private

    def authenticate_user_from_token!
    token = extract_token_from_header

    if token
      begin
        decoded_token = JWT.decode(
          token,
          Rails.application.credentials.devise_jwt_secret_key || "your_devise_jwt_secret_key",
          true,
          { algorithm: "HS256" }
        )

        # Check if token is in denylist
        jti = decoded_token[0]["jti"]
        if jti && JwtDenylist.exists?(jti: jti)
          render json: { error: "Token has been revoked" }, status: :unauthorized
          return
        end

        user_id = decoded_token[0]["id"]
        @current_user = User.find(user_id)

      rescue JWT::DecodeError, JWT::ExpiredSignature, ActiveRecord::RecordNotFound
        render json: { error: "Invalid or expired token" }, status: :unauthorized
      end
    else
      render json: { error: "Missing authentication token" }, status: :unauthorized
    end
  end

  def extract_token_from_header
    auth_header = request.headers["Authorization"]
    return nil unless auth_header

    token = auth_header.split(" ").last
    token if token.present?
  end

  def current_user
    @current_user
  end
end
