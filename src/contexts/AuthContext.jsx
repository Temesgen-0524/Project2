import React, { createContext, useContext, useState, useEffect } from "react";
import { adminCredentials } from "../data/adminCredentials";
import { apiService } from "../services/api";
import toast from "react-hot-toast";

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [adminCredential, setAdminCredential] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing session
    const savedUser = localStorage.getItem("user");
    const savedAdminCred = localStorage.getItem("adminCredential");
    
    if (savedUser) {
      const userData = JSON.parse(savedUser);
      setUser(userData);
      // Verify token is still valid
      if (userData.token) {
        verifyToken(userData.token);
      }
    }
    if (savedAdminCred) {
      setAdminCredential(JSON.parse(savedAdminCred));
    }
    
    setLoading(false);
  }, []);

  const verifyToken = async (token) => {
    try {
      await apiService.getProfile();
    } catch (error) {
      // Token is invalid, logout user
      logout();
    }
  };

  const login = async (email, password, otp = null, adminRole = null) => {
    try {
      setLoading(true);

      // Admin login
      if (adminRole) {
        const credential = adminCredentials.find(
          (cred) => cred.email.toLowerCase() === email.toLowerCase() && cred.role === adminRole
        );

        if (!credential || credential.password !== password) {
          throw new Error("Invalid admin credentials");
        }

        // Create a proper JWT-like token for admin
        const tokenPayload = {
          id: credential.id,
          email: credential.email,
          role: credential.role,
          isAdmin: true,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
        };
        
        // Create a simple token structure: header.payload.signature
        const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
        const payload = btoa(JSON.stringify(tokenPayload));
        const signature = btoa("mock-signature-for-admin");
        const mockToken = `${header}.${payload}.${signature}`;

        const adminUser = {
          id: credential.id,
          name: credential.name,
          email: credential.email,
          role: credential.role,
          isAdmin: true,
          token: mockToken,
        };

        // Log admin access
        const adminLog = {
          timestamp: new Date().toISOString(),
          adminName: credential.name,
          adminEmail: credential.email,
          action: "Admin Login",
          ipAddress: "127.0.0.1",
        };

        const existingLogs = JSON.parse(localStorage.getItem("admin_logs") || "[]");
        existingLogs.push(adminLog);
        localStorage.setItem("admin_logs", JSON.stringify(existingLogs));

        setUser(adminUser);
        setAdminCredential(credential);
        localStorage.setItem("user", JSON.stringify(adminUser));
        localStorage.setItem("adminCredential", JSON.stringify(credential));
        
        return adminUser;
      }

      // Real student login via API
      if (email && password) {
        try {
          const response = await apiService.login({ email, password });
          const studentUser = {
            ...response.user,
            token: response.token,
            isAdmin: response.user.role === "admin",
          };

          // Set the token in the API service
          localStorage.setItem("user", JSON.stringify(studentUser));
          setUser(studentUser);
          
          return studentUser;
        } catch (error) {
          // Fallback to mock login for development
          console.warn('API login failed, using mock login:', error.message);
          
          // Create a proper JWT-like token for student
          const tokenPayload = {
            id: "student_" + Date.now(),
            email: email,
            role: "student",
            isAdmin: false,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
          };
          
          const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
          const payload = btoa(JSON.stringify(tokenPayload));
          const signature = btoa("mock-signature-for-student");
          const mockToken = `${header}.${payload}.${signature}`;
          
          const studentUser = {
            id: "student_" + Date.now(),
            name: "Student User",
            email: email,
            department: "Computer Science",
            year: "4th Year",
            studentId: "DBU-2024-001",
            role: "student",
            isAdmin: false,
            token: mockToken,
          };

          localStorage.setItem("user", JSON.stringify(studentUser));
          setUser(studentUser);
          
          return studentUser;
        }
      }

      throw new Error("Invalid credentials");
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const loginWithGoogle = async () => {
    try {
      setLoading(true);
      
      // Create a proper JWT-like token for Google user
      const tokenPayload = {
        id: "google_" + Date.now(),
        email: "user@gmail.com",
        role: "student",
        isAdmin: false,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
      };
      
      const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const payload = btoa(JSON.stringify(tokenPayload));
      const signature = btoa("mock-signature-for-google");
      const mockToken = `${header}.${payload}.${signature}`;
      
      // Simulate Google login
      const googleUser = {
        id: "google_" + Date.now(),
        name: "Google User",
        email: "user@gmail.com",
        role: "student",
        isAdmin: false,
        token: mockToken,
      };

      setUser(googleUser);
      localStorage.setItem("user", JSON.stringify(googleUser));
      
      return googleUser;
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setAdminCredential(null);
    localStorage.removeItem("user");
    localStorage.removeItem("adminCredential");
    toast.success("Logged out successfully");
  };

  const value = {
    user,
    adminCredential,
    loading,
    login,
    loginWithGoogle,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};