require 'rails_helper'

RSpec.describe Api::V1::HomeController, type: :controller do
  describe 'GET #index' do
    let(:user) { create(:user) }
    let(:token) { user.generate_jwt }

    context 'with valid authentication' do
      before do
        request.headers['Authorization'] = "Bearer #{token}"
      end

      it 'returns success response' do
        get :index
        expect(response).to have_http_status(:ok)
      end

      it 'returns welcome message' do
        get :index
        json_response = JSON.parse(response.body)

        expect(json_response['message']).to eq('Welcome to Study Buddy Application')
      end

      it 'returns correct response format' do
        get :index
        json_response = JSON.parse(response.body)

        expect(json_response).to have_key('message')
        expect(json_response['message']).to be_a(String)
      end
    end

    context 'without authentication token' do
      before do
        request.headers['Authorization'] = nil
      end

      it 'returns unauthorized status' do
        get :index
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        get :index
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Missing authentication token')
      end
    end

    context 'with invalid token' do
      before do
        request.headers['Authorization'] = 'Bearer invalid_token'
      end

      it 'returns unauthorized status' do
        get :index
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        get :index
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Invalid or expired token')
      end
    end

    context 'with expired token' do
      let(:expired_token) do
        JWT.encode(
          {
            id: user.id,
            email: user.email,
            jti: SecureRandom.uuid,
            exp: 1.day.ago.to_i
          },
          Rails.application.credentials.devise_jwt_secret_key || 'your_devise_jwt_secret_key'
        )
      end

      before do
        request.headers['Authorization'] = "Bearer #{expired_token}"
      end

      it 'returns unauthorized status' do
        get :index
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        get :index
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Invalid or expired token')
      end
    end

    context 'with revoked token' do
      let(:token) { user.generate_jwt }

      before do
        request.headers['Authorization'] = "Bearer #{token}"
        # Revoke the token
        jti = JWT.decode(
          token,
          Rails.application.credentials.devise_jwt_secret_key || 'your_devise_jwt_secret_key',
          false
        )[0]['jti']
        JwtDenylist.create!(jti: jti, exp: 1.day.from_now)
      end

      it 'returns unauthorized status' do
        get :index
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns token revoked error' do
        get :index
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Token has been revoked')
      end
    end
  end
end
