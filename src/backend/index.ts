import express from "express";
import { random } from "./utils.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { ContentModel, LinkModel, UserModel } from "./db.js";
import { JWT_PASSWORD } from "./config.js";
import { userMiddleware } from "./middleware.js";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

const authSchema = z.object({
    username: z.string().trim().min(1),
    password: z.string().min(8)
});

app.post("/api/v1/signup", async (req, res) => {
    const result = authSchema.safeParse(req.body);
    if (!result.success) {
        res.status(400).json({
            message: "Username and password are invalid"
        });
        return;
    }

    const { username, password } = result.data;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await UserModel.create({
            username,
            password: hashedPassword
        });

        res.json({
            message: "User signed up"
        });
    } catch (e) {
        res.status(411).json({
            message: "User already exists"
        });
    }
});

app.post("/api/v1/signin", async (req, res) => {
    const result = authSchema.safeParse(req.body);
    if (!result.success) {
        res.status(400).json({
            message: "Username and password are invalid"
        });
        return;
    }

    const { username, password } = result.data;
    const existingUser = await UserModel.findOne({ username });
    const passwordMatches = existingUser
        ? await bcrypt.compare(password, existingUser.password ?? "")
        : false;

    if (existingUser && passwordMatches) {
        const token = jwt.sign({
            id: existingUser._id
        }, JWT_PASSWORD);

        res.json({
            token
        });
    } else {
        res.status(403).json({
            message: "Incorrect credentials"
        });
    }
});

app.post("/api/v1/content", userMiddleware, async (req, res) => {
    const link = req.body.link;
    const type = req.body.type;
    await ContentModel.create({
        link,
        type,
        title: req.body.title,
        userId: req.userId,
        tags: []
    });

    res.json({
        message: "Content added"
    });
});

app.get("/api/v1/content", userMiddleware, async (req, res) => {
    const content = await ContentModel.find({
        userId: req.userId
    }).populate("userId", "username");
    res.json({
        content
    });
});

app.delete("/api/v1/content", userMiddleware, async (req, res) => {
    const contentId = req.body.contentId;

    await ContentModel.deleteMany({
        _id: contentId,
        userId: req.userId
    });

    res.json({
        message: "Deleted"
    });
});

app.post("/api/v1/brain/share", userMiddleware, async (req, res) => {
    const share = req.body.share;
    if (share) {
        const existingLink = await LinkModel.findOne({
            userId: req.userId
        });

        if (existingLink) {
            res.json({
                hash: existingLink.hash
            });
            return;
        }

        const hash = random(10);
        await LinkModel.create({
            userId: req.userId,
            hash
        });

        res.json({
            hash
        });
    } else {
        await LinkModel.deleteOne({
            userId: req.userId
        });

        res.json({
            message: "Removed link"
        });
    }
});

app.get("/api/v1/brain/:shareLink", async (req, res) => {
    const hash = req.params.shareLink;
    const link = await LinkModel.findOne({ hash });

    if (!link) {
        res.status(411).json({
            message: "Sorry incorrect input"
        });
        return;
    }

    const content = await ContentModel.find({
        userId: link.userId
    });
    const user = await UserModel.findOne({
        _id: link.userId
    });

    if (!user) {
        res.status(411).json({
            message: "user not found, error should ideally not happen"
        });
        return;
    }

    res.json({
        username: user.username,
        content
    });
});

app.listen(3000);
