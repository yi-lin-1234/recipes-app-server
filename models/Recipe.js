import { DataTypes } from "sequelize";
import sequelize from "../config/db.js";

// Define Recipe model
const Recipe = sequelize.define("Recipe", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  cuisine: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  ingredients: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  instructions: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  recipePictureUrl: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  totalPrepTime: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  difficultyLevel: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  likes: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
  },
  notes: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

export default Recipe;
