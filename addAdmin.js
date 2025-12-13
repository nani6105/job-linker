const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User.js');

const MONGODB_URI = "mongodb+srv://nanialthi7791_db_user:akkianki%40123@cluster0.fkioc5b.mongodb.net/joblinkerDB?retryWrites=true&w=majority";

mongoose.connect(MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error(err));

const createAdmin = async () => {
  const email = "23a51a05k3@gmail.com";
  const password = "joblinker234";
  const hashedPassword = await bcrypt.hash(password, 10);

  const admin = new User({ email, password: hashedPassword, role: "admin" });
  await admin.save();
  console.log("Admin user created!");
  mongoose.disconnect();
};

createAdmin();
