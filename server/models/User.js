import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: /^[a-zA-Z0-9._%+-]+@gmail\.com$/i
    },

    password: {
      type: String,
      required: true,
      minlength: 8,
      maxlength: 128,
      select: false
    },

    publicKey: {
      type: String,
      default: null
    },

    encryptedPrivateKey: {
      type: String,
      default: null,
      select: false
    },

    keySalt: {
      type: String,
      default: null,
      select: false
    },

    keyIV: {
      type: String,
      default: null,
      select: false
    },

    keyProtectionAlgorithm: {
      type: String,
      default: "PBKDF2-SHA256",
      enum: ["PBKDF2-SHA256"]
    },

    keyProtectionIterations: {
      type: Number,
      default: 600000,
      min: 600000
    },

    keyVersion: {
      type: Number,
      default: 1,
      min: 1
    },

    tokenVersion: {
      type: Number,
      default: 0,
      min: 0,
      validate: {
        validator: Number.isInteger,
        message: "Token version must be an integer."
      }
    },

    // Role-based access control
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
      index: true
    },

    isOnline: {
      type: Boolean,
      default: false
    },

    lastSeen: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model("User", userSchema);

export default User;