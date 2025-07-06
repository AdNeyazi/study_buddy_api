module Api
  module V1
    class HomeController < ApplicationController
      before_action :authenticate_user_from_token!

      def index
        render json: {
          message: "Welcome to Study Buddy Application"
        }, status: :ok
      end
    end
  end
end
