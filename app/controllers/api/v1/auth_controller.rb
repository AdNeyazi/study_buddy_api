module Api
  module V1
    class AuthController < ApplicationController
      skip_before_action :authenticate_user_from_token!, only: [ :signup, :login ]

      def signup
        user = User.new(user_params)

        if user.save
          # Generate JWT token after successful signup
          token = user.generate_jwt
          render json: {
            message: "User created successfully",
            user: {
              id: user.id,
              email: user.email
            },
            token: token
          }, status: :created
        else
          render json: {
            error: "User creation failed",
            details: user.errors.full_messages
          }, status: :unprocessable_entity
        end
      end

      def login
        user = User.find_by(email: params[:user][:email])

        if user&.valid_password?(params[:user][:password])
          # Generate JWT token after successful login
          token = user.generate_jwt
          render json: {
            message: "Login successful",
            user: {
              id: user.id,
              email: user.email
            },
            token: token
          }, status: :ok
        else
          render json: {
            error: "Invalid email or password"
          }, status: :unauthorized
        end
      end

      def logout
        # Revoke the current JWT token
        if current_user
          # Add the current token to the denylist
          jti = extract_jti_from_token
          if jti
            JwtDenylist.create!(
              jti: jti,
              exp: Time.at(extract_exp_from_token).to_datetime
            )
          end
        end

        render json: {
          message: "Logged out successfully"
        }, status: :ok
      end

      def me
        render json: {
          user: {
            id: current_user.id,
            email: current_user.email
          }
        }, status: :ok
      end

      private

      def user_params
        params.require(:user).permit(:email, :password, :password_confirmation)
      end

      def extract_jti_from_token
        token = extract_token_from_header
        return nil unless token

        begin
          decoded_token = JWT.decode(
            token,
            Rails.application.credentials.devise_jwt_secret_key || "your_devise_jwt_secret_key",
            false # Don't verify signature for extraction
          )
          decoded_token[0]["jti"]
        rescue JWT::DecodeError
          nil
        end
      end

      def extract_exp_from_token
        token = extract_token_from_header
        return nil unless token

        begin
          decoded_token = JWT.decode(
            token,
            Rails.application.credentials.devise_jwt_secret_key || "your_devise_jwt_secret_key",
            false # Don't verify signature for extraction
          )
          decoded_token[0]["exp"]
        rescue JWT::DecodeError
          nil
        end
      end
    end
  end
end
