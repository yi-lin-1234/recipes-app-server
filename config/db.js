import { Sequelize } from "sequelize";

const sequelize = new Sequelize(
  "postgresql://postgres:9RHkXSv4NNX1ZtvyUDOO@containers-us-west-59.railway.app:5817/railway"
);

try {
  await sequelize.authenticate();
  console.log("Connection has been established successfully.");
} catch (error) {
  console.error("Unable to connect to the database:", error);
}

export default sequelize;
