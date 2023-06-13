import express from "express";
import cors from "cors";
import morgan from "morgan";
import sequelize from "./config/db.js";
import User from "./models/User.js";
import Recipe from "./models/Recipe.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Op } from "sequelize";
import cookieParser from "cookie-parser";

const app = express();

// Configure CORS
const corsOptions = {
  origin: "http://localhost:3000", // specify the exact origin
  credentials: true, // allow credentials
};

// middleware
app.use(cors(corsOptions));
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());

const jwt_secret =
  "b09a1828add71c267f346f226e630dbf4e5519b608e08cbc4016d2d51027660eb57985e696125ee232cb68921baaf5126dc9dcdb566ac12025642eb08d90f0b8";

Recipe.belongsTo(User);
User.hasMany(Recipe);

sequelize
  .sync()
  .then(() => {
    console.log("user and recipe table created successfully!");
  })
  .catch((error) => {
    console.error("unable to create table : ", error);
  });

//=====================( middleware )===========================
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  // Better logging format.
  console.log(`Cookies: ${JSON.stringify(req.cookies)}`);

  // Use '!' instead of '== null' to catch both null and undefined.
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, jwt_secret, (err, jwtPayload) => {
    if (err) {
      console.log("Failed to verify token:", err);
      return res.status(403).json({ message: "Failed to authenticate token" });
    }

    // Assigning user id to req object can be useful for downstream middleware/routes.
    req.userId = jwtPayload.id;

    console.log("successfully verify token");
    next();
  });
}

//=====================( for frontend protected route )===========================
app.post("/protectedRouteVerification", async (req, res) => {
  const token = req.cookies.token;

  // Token should be checked for both null and undefined
  if (!token) return res.sendStatus(401); // Unauthorized

  // It is good to separate the secret key from the code, possibly in environment variables.
  jwt.verify(token, jwt_secret, async (err, jwtPayload) => {
    if (err) return res.sendStatus(403); // Forbidden

    const id = jwtPayload.id;
    req.id = id;

    // Try-catch block for handling DB errors
    try {
      // Find the user by username
      const user = await User.findOne({ where: { id: id } });

      // Check if the user was found
      if (!user) return res.status(404).json({ message: "User not found" });

      const userResponse = {
        id: user.id,
        username: user.username,
        email: user.email,
        profilePictureUrl: user.profilePictureUrl,
        aboutMe: user.aboutMe,
      };
      res.status(200).json({
        message: "User logged in successfully",
        user: userResponse,
      });
    } catch (error) {
      // Database error or server error
      return res.status(500).json({ message: "Internal Server Error" });
    }
  });
});

//====================( sign up )================================

app.post("/signup", async (req, res) => {
  try {
    console.log(req.body);
    const { username, email, password } = req.body;
    // Check if all fields are present
    if (!username || !email || !password) {
      return res.status(400).json({ message: "all fields are required" });
    }

    // Check if email is valid
    const emailRegex = /\S+@\S+\.\S+/; // simple regex for checking email validity
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "invalid email format" });
    }

    // Check if password is of sufficient length
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "password must be at least 6 characters" });
    }

    // check if email already exist
    const emailExists = await User.findOne({ where: { email: email } });

    if (emailExists) {
      return res.status(403).json({
        message: "User already exists",
        statusCode: 403,
        errors: {
          email: "user with that email already exists",
        },
      });
    }

    // Check if username already exists
    const usernameExists = await User.findOne({ where: { username } });

    if (usernameExists) {
      return res.status(403).json({
        message: "Username already taken",
        statusCode: 403,
        errors: {
          username: "username already taken",
        },
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      aboutMe:
        "Welcome to my culinary world! Get ready to explore delicious recipes, cooking tips, and techniques. Let's create amazing dishes together and make cooking a joyous experience for everyone. Happy cooking!",
      profilePictureUrl:
        "https://res.cloudinary.com/yilin1234/image/upload/v1685746074/Generic-Profile-Image_vlk1kx.png",
    });

    // We need to remove the password from the user object.
    const userResponse = {
      id: user.id,
      username: user.username,
      email: user.email,
      profilePictureUrl: user.profilePictureUrl,
      aboutMe: user.aboutMe,
    };

    // After the user is created, sign a JWT token
    const token = jwt.sign({ id: user.id }, jwt_secret, {
      expiresIn: "24h",
    });

    res.cookie("token", token, { httpOnly: true });
    res.status(201).json({
      message: "user registered successfully",
      user: userResponse,
    });
  } catch (error) {
    res.status(500).json({ message: "error registering user" });
  }
});
//==========================( log in )==============================

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ where: { email: email } });

    // If the user doesn't exist or the password is incorrect
    if (!user) {
      return res.status(401).json({ message: "no such user with given email" });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "wrong password" });
    }

    // We need to remove the password from the user object.
    const userResponse = {
      id: user.id,
      username: user.username,
      email: user.email,
      profilePictureUrl: user.profilePictureUrl,
      aboutMe: user.aboutMe,
    };

    // Generate a JWT token
    const token = jwt.sign({ id: user.id }, jwt_secret, {
      expiresIn: "24h",
    });

    res.cookie("token", token, { httpOnly: true });
    res.status(200).json({
      message: "user log in successfully",
      user: userResponse,
    });
  } catch (error) {
    res.status(500).json({ message: "error logging in" });
  }
});

//===================( logout )===========================

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ message: "user logged out successfully" });
});

//===================( Create new recipe )===========================

app.post("/recipe", authenticateToken, async (req, res) => {
  try {
    const {
      name,
      cuisine,
      ingredients,
      instructions,
      recipePictureUrl,
      totalPrepTime,
      difficultyLevel,
      notes,
    } = req.body;

    // Check if all fields are present
    if (
      !name ||
      !cuisine ||
      !ingredients ||
      !instructions ||
      !recipePictureUrl ||
      !totalPrepTime ||
      !difficultyLevel ||
      !notes
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Retrieve the user id from the JWT token
    const userId = req.id;

    // Create a new recipe
    const recipe = await Recipe.create({
      name,
      cuisine,
      ingredients,
      instructions,
      recipePictureUrl,
      totalPrepTime,
      difficultyLevel,
      notes,
      UserId: userId,
    });

    res.status(201).json({
      message: "Recipe created successfully",
      recipe: recipe,
    });
  } catch (error) {
    console.error("Error creating recipe", error);
    res.status(500).json({ message: "Error creating recipe" });
  }
});

//===================( Get all recipes )===========================

app.get("/recipes", authenticateToken, async (req, res) => {
  try {
    // Retrieve all recipes
    const recipes = await Recipe.findAll();

    // If no recipes found, return appropriate message
    if (!recipes) {
      return res.status(404).json({ message: "No recipes found" });
    }

    res.status(200).json({
      message: "Recipes fetched successfully",
      recipes: recipes,
    });
  } catch (error) {
    console.error("Error fetching recipes", error);
    res.status(500).json({ message: "Error fetching recipes" });
  }
});

//===================( Get a recipe )===========================

app.get("/recipe/:id", authenticateToken, async (req, res) => {
  try {
    // Retrieve the recipe id from the request parameters
    const recipeId = req.params.id;

    // Find the recipe
    const recipe = await Recipe.findByPk(recipeId);

    // If no recipe found, return appropriate message
    if (!recipe) {
      return res.status(404).json({ message: "Recipe not found" });
    }

    res.status(200).json({
      message: "Recipe fetched successfully",
      recipe: recipe,
    });
  } catch (error) {
    console.error("Error fetching recipe", error);
    res.status(500).json({ message: "Error fetching recipe" });
  }
});

//===================( Get all distinct cuisines )===========================

app.get("/DistinctCuisines", authenticateToken, async (req, res) => {
  try {
    const [results, metadata] = await sequelize.query(
      'SELECT DISTINCT cuisine FROM "Recipes"'
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: "No cuisines found" });
    }

    const cuisines = results.map((result) => result.cuisine);

    res.status(200).json({
      message: "Cuisines fetched successfully",
      cuisines: cuisines,
    });
  } catch (error) {
    console.error("Error fetching cuisines", error);
    res.status(500).json({ message: "Error fetching cuisines" });
  }
});

//===================( Get all recipes by cuisine )===========================

//http://localhost:3000/SearchRecipesByCuisine?cuisine=American

app.get("/SearchRecipesByCuisine", authenticateToken, async (req, res) => {
  try {
    const { cuisine } = req.query;

    if (!cuisine) {
      return res.status(400).json({ message: "Cuisine is required" });
    }

    // Retrieve all recipes for the given cuisine
    const recipes = await Recipe.findAll({ where: { cuisine: cuisine } });

    // If no recipes found, return appropriate message
    if (!recipes || recipes.length === 0) {
      return res
        .status(404)
        .json({ message: `No recipes found for cuisine: ${cuisine}` });
    }

    res.status(200).json({
      message: "Recipes fetched successfully",
      recipes: recipes,
    });
  } catch (error) {
    console.error("Error fetching recipes", error);
    res.status(500).json({ message: "Error fetching recipes" });
  }
});

//===================( Get all recipes by difficultyLevel )===========================

//http://localhost:3000/SearchRecipesByDifficultyLevel?difficultyLevel=easy

app.get(
  "/SearchRecipesByDifficultyLevel",
  authenticateToken,
  async (req, res) => {
    try {
      const { difficultyLevel } = req.query;

      // List of valid difficulty levels, you should update this according to your app's needs
      const validDifficultyLevels = ["easy", "medium", "hard"];

      // Validate difficultyLevel input
      if (
        !difficultyLevel ||
        !validDifficultyLevels.includes(difficultyLevel)
      ) {
        return res
          .status(400)
          .json({ message: "Valid difficulty level is required." });
      }

      // Retrieve all recipes for the given difficulty level
      const recipes = await Recipe.findAll({
        where: { difficultyLevel: difficultyLevel },
      });

      // If no recipes found, return appropriate message
      if (!recipes || recipes.length === 0) {
        return res.status(404).json({
          message: `No recipes found for difficulty level: ${difficultyLevel}`,
        });
      }

      res.status(200).json({
        message: "Recipes fetched successfully",
        recipes: recipes,
      });
    } catch (error) {
      console.error("Error fetching recipes", error);
      res.status(500).json({ message: "Error fetching recipes" });
    }
  }
);

//===================( Search recipes by name )===========================

//http://localhost:3000/recipes/search?name=Pizza

app.get("/recipes/search", authenticateToken, async (req, res) => {
  try {
    const { name } = req.query;

    if (!name) {
      return res.status(400).json({ message: "Recipe name is required." });
    }

    // Find recipes by name
    const recipes = await Recipe.findAll({
      where: {
        name: {
          [Op.iLike]: "%" + name + "%",
        },
      },
    });

    // If no recipes found, return appropriate message
    if (!recipes || recipes.length === 0) {
      return res
        .status(404)
        .json({ message: `No recipes found with name: ${name}` });
    }

    res.status(200).json({
      message: "Recipes fetched successfully",
      recipes: recipes,
    });
  } catch (error) {
    console.error("Error fetching recipes", error);
    res.status(500).json({ message: "Error fetching recipes" });
  }
});

//===================( Edit a recipe )===========================

app.put("/recipe/:id", authenticateToken, async (req, res) => {
  try {
    const {
      name,
      cuisine,
      ingredients,
      instructions,
      recipePictureUrl,
      totalPrepTime,
      difficultyLevel,
      notes,
    } = req.body;

    // Retrieve the recipe id from the request parameters
    const recipeId = req.params.id;

    // Find the recipe
    const recipe = await Recipe.findByPk(recipeId);

    // If no recipe found, return appropriate message
    if (!recipe) {
      return res.status(404).json({ message: "Recipe not found" });
    }

    // Check if the user is the owner of the recipe
    if (recipe.UserId !== req.id) {
      return res.status(403).json({ message: "Unauthorized action" });
    }

    // Update the recipe
    await recipe.update({
      name,
      cuisine,
      ingredients,
      instructions,
      recipePictureUrl,
      totalPrepTime,
      difficultyLevel,
      notes,
    });

    res.status(200).json({
      message: "Recipe updated successfully",
      recipe: recipe,
    });
  } catch (error) {
    console.error("Error updating recipe", error);
    res.status(500).json({ message: "Error updating recipe" });
  }
});

//===================( Increment like for a recipe )===========================

//http://localhost:3000/recipes/like/:id

app.patch("/recipes/like/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ message: "Recipe ID is required." });
    }

    // Find the recipe by id
    const recipe = await Recipe.findOne({ where: { id: id } });

    // If no recipe found, return appropriate message
    if (!recipe) {
      return res
        .status(404)
        .json({ message: `No recipe found with id: ${id}` });
    }

    // Increment like count
    const updatedRecipe = await recipe.increment("likes", { by: 1 });

    res.status(200).json({
      message: "Recipe like incremented successfully",
      recipe: updatedRecipe,
    });
  } catch (error) {
    console.error("Error incrementing like", error);
    res.status(500).json({ message: "Error incrementing like" });
  }
});

//===================( Delete a recipe by id )===========================

//http://localhost:3000/recipes/:id

app.delete("/recipes/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ message: "Recipe ID is required." });
    }

    // Find the recipe by id
    const recipe = await Recipe.findOne({ where: { id: id } });

    // If no recipe found, return appropriate message
    if (!recipe) {
      return res
        .status(404)
        .json({ message: `No recipe found with id: ${id}` });
    }

    // Delete the recipe
    await recipe.destroy();

    res.status(200).json({
      message: "Recipe deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting recipe", error);
    res.status(500).json({ message: "Error deleting recipe" });
  }
});

const port = process.env.PORT || 8000;

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
