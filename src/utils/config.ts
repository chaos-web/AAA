export default () => ({
    port: parseInt(process.env.PORT, 10) || 3000,
    database: {
      dialect: process.env.DATABASE_DIALECT,
      host: process.env.DATABASE_HOST,
      port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
      username: process.env.DATABASE_USERNAME,
      password: process.env.DATABASE_PASSWORD,
      name: process.env.DATABASE_NAME,
      synchronize: process.env.DATABASE_SYNCHRONIZE,
    },
    session: {
      secret: process.env.SECRET_KEY,
      expiresIn: process.env.SECRET_EXPIR,
    },
    mail: {
      email: process.env.EMAIL,
      secret: process.env.CLIENT_SECRET,
      service: process.env.CLIENT_SERVICE,
    },
  });
  