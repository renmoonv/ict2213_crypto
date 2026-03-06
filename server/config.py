class Config:
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://crypto_user:cryptopass@localhost:3306/applied_crypto"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "dev-secret-key" # THIS NEED TO CHANGE