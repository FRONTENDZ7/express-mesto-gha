const userRouter = require("express").Router();

const {
  getUserList,
  getUserId,
  createUser,
  updateUserData,
  updateUserAvatar,
} = require("../controllers/users");

userRouter.get("/", getUserList);
userRouter.get("/:userId", getUserId);
userRouter.post("/", createUser);
userRouter.patch("/me", updateUserData);
userRouter.patch("/me/avatar", updateUserAvatar);

module.exports = userRouter;
