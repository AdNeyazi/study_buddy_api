require 'rails_helper'

RSpec.describe Api::V1::AuthController, type: :controller do
  describe 'POST #signup' do
    context 'with valid parameters' do
      let(:valid_params) do
        {
          user: {
            email: 'test@example.com',
            password: 'password123',
            password_confirmation: 'password123'
          }
        }
      end

      it 'creates a new user' do
        expect {
          post :signup, params: valid_params
        }.to change(User, :count).by(1)
      end

      it 'returns success response' do
        post :signup, params: valid_params
        expect(response).to have_http_status(:created)
      end

      it 'returns user data and token' do
        post :signup, params: valid_params
        json_response = JSON.parse(response.body)

        expect(json_response['message']).to eq('User created successfully')
        expect(json_response['user']['email']).to eq('test@example.com')
        expect(json_response['token']).to be_present
      end
    end

    context 'with invalid parameters' do
      let(:invalid_params) do
        {
          user: {
            email: 'invalid-email',
            password: '123',
            password_confirmation: '123'
          }
        }
      end

      it 'does not create a user' do
        expect {
          post :signup, params: invalid_params
        }.not_to change(User, :count)
      end

      it 'returns unprocessable entity status' do
        post :signup, params: invalid_params
        expect(response).to have_http_status(:unprocessable_entity)
      end

      it 'returns error details' do
        post :signup, params: invalid_params
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('User creation failed')
        expect(json_response['details']).to be_present
      end
    end

    context 'with mismatched password confirmation' do
      let(:params_with_mismatch) do
        {
          user: {
            email: 'test@example.com',
            password: 'password123',
            password_confirmation: 'differentpassword'
          }
        }
      end

      it 'does not create a user' do
        expect {
          post :signup, params: params_with_mismatch
        }.not_to change(User, :count)
      end

      it 'returns error response' do
        post :signup, params: params_with_mismatch
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end
  end

  describe 'POST #login' do
    let!(:user) { create(:user, email: 'test@example.com', password: 'password123') }

    context 'with valid credentials' do
      let(:valid_params) do
        {
          user: {
            email: 'test@example.com',
            password: 'password123'
          }
        }
      end

      it 'returns success response' do
        post :login, params: valid_params
        expect(response).to have_http_status(:ok)
      end

      it 'returns user data and token' do
        post :login, params: valid_params
        json_response = JSON.parse(response.body)

        expect(json_response['message']).to eq('Login successful')
        expect(json_response['user']['email']).to eq('test@example.com')
        expect(json_response['token']).to be_present
      end
    end

    context 'with invalid email' do
      let(:invalid_email_params) do
        {
          user: {
            email: 'wrong@example.com',
            password: 'password123'
          }
        }
      end

      it 'returns unauthorized status' do
        post :login, params: invalid_email_params
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        post :login, params: invalid_email_params
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Invalid email or password')
      end
    end

    context 'with invalid password' do
      let(:invalid_password_params) do
        {
          user: {
            email: 'test@example.com',
            password: 'wrongpassword'
          }
        }
      end

      it 'returns unauthorized status' do
        post :login, params: invalid_password_params
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        post :login, params: invalid_password_params
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Invalid email or password')
      end
    end
  end

  describe 'DELETE #logout' do
    let(:user) { create(:user) }
    let(:token) { user.generate_jwt }

    before do
      request.headers['Authorization'] = "Bearer #{token}"
    end

    it 'returns success response' do
      delete :logout
      expect(response).to have_http_status(:ok)
    end

    it 'returns logout message' do
      delete :logout
      json_response = JSON.parse(response.body)

      expect(json_response['message']).to eq('Logged out successfully')
    end

    it 'adds token to denylist' do
      expect {
        delete :logout
      }.to change(JwtDenylist, :count).by(1)
    end
  end

  describe 'GET #me' do
    let(:user) { create(:user) }
    let(:token) { user.generate_jwt }

    before do
      request.headers['Authorization'] = "Bearer #{token}"
    end

    it 'returns success response' do
      get :me
      expect(response).to have_http_status(:ok)
    end

    it 'returns current user data' do
      get :me
      json_response = JSON.parse(response.body)

      expect(json_response['user']['id']).to eq(user.id)
      expect(json_response['user']['email']).to eq(user.email)
    end

    context 'without authentication token' do
      before do
        request.headers['Authorization'] = nil
      end

      it 'returns unauthorized status' do
        get :me
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        get :me
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Missing authentication token')
      end
    end

    context 'with invalid token' do
      before do
        request.headers['Authorization'] = 'Bearer invalid_token'
      end

      it 'returns unauthorized status' do
        get :me
        expect(response).to have_http_status(:unauthorized)
      end

      it 'returns error message' do
        get :me
        json_response = JSON.parse(response.body)

        expect(json_response['error']).to eq('Invalid or expired token')
      end
    end
  end
end
