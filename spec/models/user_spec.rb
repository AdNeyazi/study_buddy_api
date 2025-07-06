require 'rails_helper'

RSpec.describe User, type: :model do
  describe 'validations' do
    it 'is valid with valid attributes' do
      user = build(:user)
      expect(user).to be_valid
    end

    it 'is not valid without an email' do
      user = build(:user, email: nil)
      expect(user).not_to be_valid
      expect(user.errors[:email]).to include("can't be blank")
    end

    it 'is not valid with an invalid email format' do
      user = build(:user, email: 'invalid-email')
      expect(user).not_to be_valid
      expect(user.errors[:email]).to include('is invalid')
    end

    it 'is not valid without a password' do
      user = build(:user, password: nil)
      expect(user).not_to be_valid
      expect(user.errors[:password]).to include("can't be blank")
    end

    it 'is not valid with a short password' do
      user = build(:user, password: '123', password_confirmation: '123')
      expect(user).not_to be_valid
      expect(user.errors[:password]).to include('is too short (minimum is 6 characters)')
    end

    it 'is not valid when password confirmation does not match' do
      user = build(:user, password: 'password123', password_confirmation: 'different')
      expect(user).not_to be_valid
      expect(user.errors[:password_confirmation]).to include("doesn't match Password")
    end

    it 'is not valid with a duplicate email' do
      create(:user, email: 'test@example.com')
      user = build(:user, email: 'test@example.com')
      expect(user).not_to be_valid
      expect(user.errors[:email]).to include('has already been taken')
    end
  end

  describe 'devise modules' do
    it 'includes database_authenticatable' do
      expect(User.devise_modules).to include(:database_authenticatable)
    end

    it 'includes registerable' do
      expect(User.devise_modules).to include(:registerable)
    end

    it 'includes recoverable' do
      expect(User.devise_modules).to include(:recoverable)
    end

    it 'includes rememberable' do
      expect(User.devise_modules).to include(:rememberable)
    end

    it 'includes validatable' do
      expect(User.devise_modules).to include(:validatable)
    end

    it 'includes jwt_authenticatable' do
      expect(User.devise_modules).to include(:jwt_authenticatable)
    end
  end

  describe '#generate_jwt' do
    let(:user) { create(:user) }

    it 'generates a valid JWT token' do
      token = user.generate_jwt
      expect(token).to be_a(String)
      expect(token.split('.').length).to eq(3) # JWT has 3 parts
    end

    it 'includes user id in the token payload' do
      token = user.generate_jwt
      decoded_token = JWT.decode(
        token,
        Rails.application.credentials.devise_jwt_secret_key || 'your_devise_jwt_secret_key',
        false
      )
      expect(decoded_token[0]['id']).to eq(user.id)
    end

    it 'includes user email in the token payload' do
      token = user.generate_jwt
      decoded_token = JWT.decode(
        token,
        Rails.application.credentials.devise_jwt_secret_key || 'your_devise_jwt_secret_key',
        false
      )
      expect(decoded_token[0]['email']).to eq(user.email)
    end

    it 'includes jti in the token payload' do
      token = user.generate_jwt
      decoded_token = JWT.decode(
        token,
        Rails.application.credentials.devise_jwt_secret_key || 'your_devise_jwt_secret_key',
        false
      )
      expect(decoded_token[0]['jti']).to be_present
    end

    it 'includes expiration time in the token payload' do
      token = user.generate_jwt
      decoded_token = JWT.decode(
        token,
        Rails.application.credentials.devise_jwt_secret_key || 'your_devise_jwt_secret_key',
        false
      )
      expect(decoded_token[0]['exp']).to be_present
      expect(decoded_token[0]['exp']).to be > Time.current.to_i
    end
  end

  describe 'password validation' do
    it 'validates password length' do
      user = build(:user, password: '12345', password_confirmation: '12345')
      expect(user).not_to be_valid
      expect(user.errors[:password]).to include('is too short (minimum is 6 characters)')
    end

    it 'accepts password with minimum length' do
      user = build(:user, password: '123456', password_confirmation: '123456')
      expect(user).to be_valid
    end
  end

  describe 'email uniqueness' do
    it 'enforces case-insensitive email uniqueness' do
      create(:user, email: 'test@example.com')
      user = build(:user, email: 'TEST@EXAMPLE.COM')
      expect(user).not_to be_valid
      expect(user.errors[:email]).to include('has already been taken')
    end
  end
end
