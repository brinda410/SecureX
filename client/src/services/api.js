import axios from "axios";
import { getCryptoSession } from "../utils/cryptoSession.js";

const API_BASE_URL =
    import.meta.env.VITE_API_URL || "/api"

const API = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        "Content-Type": "application/json"
    },
    timeout: 15000
});

// Attach the in-memory JWT to every authenticated request.
API.interceptors.request.use(
    (config) => {
        const { token } = getCryptoSession();

        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        return config;
    },
    (error) => Promise.reject(error)
);

export default API;