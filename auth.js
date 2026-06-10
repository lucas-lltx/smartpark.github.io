// auth.js
import { 
  getAuth, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  onAuthStateChanged,
  GoogleAuthProvider,
  signInWithPopup,
  updateEmail,
  updatePassword,
  deleteUser,
  reauthenticateWithCredential,
  EmailAuthProvider
} from "firebase/auth";
import { app } from "./firebase-config.js"; // Your Firebase config file

// Initialize Firebase Authentication
const auth = getAuth(app);

// Email/Password Sign Up
export const signUp = async (email, password, displayName) => {
  try {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;
    
    // Update user profile with display name
    if (displayName) {
      await updateProfile(user, { displayName });
    }
    
    // Send email verification
    await sendEmailVerification(user);
    
    return { success: true, user, message: "Account created successfully! Please verify your email." };
  } catch (error) {
    return { success: false, error: error.message, code: error.code };
  }
};

// Email/Password Sign In
export const signIn = async (email, password) => {
  try {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;
    
    // Check if email is verified
    if (!user.emailVerified) {
      await signOut(auth);
      return { success: false, error: "Please verify your email before signing in." };
    }
    
    return { success: true, user, message: "Signed in successfully!" };
  } catch (error) {
    let message = "Invalid email or password.";
    if (error.code === 'auth/user-not-found') message = "No account found with this email.";
    if (error.code === 'auth/wrong-password') message = "Incorrect password.";
    if (error.code === 'auth/too-many-requests') message = "Too many failed attempts. Try again later.";
    
    return { success: false, error: message, code: error.code };
  }
};

// Sign Out
export const logOut = async () => {
  try {
    await signOut(auth);
    return { success: true, message: "Signed out successfully!" };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Password Reset
export const resetPassword = async (email) => {
  try {
    await sendPasswordResetEmail(auth, email);
    return { success: true, message: "Password reset email sent! Check your inbox." };
  } catch (error) {
    let message = "Failed to send reset email.";
    if (error.code === 'auth/user-not-found') message = "No account found with this email.";
    
    return { success: false, error: message, code: error.code };
  }
};

// Resend Email Verification
export const resendVerificationEmail = async () => {
  try {
    const user = auth.currentUser;
    if (user) {
      await sendEmailVerification(user);
      return { success: true, message: "Verification email sent!" };
    }
    return { success: false, error: "No user logged in." };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Update User Profile
export const updateUserProfile = async (displayName, photoURL) => {
  try {
    const user = auth.currentUser;
    if (user) {
      await updateProfile(user, { displayName, photoURL });
      return { success: true, user, message: "Profile updated successfully!" };
    }
    return { success: false, error: "No user logged in." };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Update Email (requires re-authentication)
export const updateUserEmail = async (newEmail, password) => {
  try {
    const user = auth.currentUser;
    if (user) {
      // Re-authenticate user before changing email
      const credential = EmailAuthProvider.credential(user.email, password);
      await reauthenticateWithCredential(user, credential);
      
      await updateEmail(user, newEmail);
      await sendEmailVerification(user); // Send verification to new email
      
      return { success: true, message: "Email updated! Please verify your new email address." };
    }
    return { success: false, error: "No user logged in." };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Update Password (requires re-authentication)
export const updateUserPassword = async (currentPassword, newPassword) => {
  try {
    const user = auth.currentUser;
    if (user) {
      // Re-authenticate user before changing password
      const credential = EmailAuthProvider.credential(user.email, currentPassword);
      await reauthenticateWithCredential(user, credential);
      
      await updatePassword(user, newPassword);
      return { success: true, message: "Password updated successfully!" };
    }
    return { success: false, error: "No user logged in." };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Delete User Account (requires re-authentication)
export const deleteUserAccount = async (password) => {
  try {
    const user = auth.currentUser;
    if (user) {
      // Re-authenticate user before deleting account
      const credential = EmailAuthProvider.credential(user.email, password);
      await reauthenticateWithCredential(user, credential);
      
      await deleteUser(user);
      return { success: true, message: "Account deleted successfully!" };
    }
    return { success: false, error: "No user logged in." };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Google Sign In
export const signInWithGoogle = async () => {
  try {
    const provider = new GoogleAuthProvider();
    provider.addScope('profile');
    provider.addScope('email');
    
    const result = await signInWithPopup(auth, provider);
    const user = result.user;
    
    return { success: true, user, message: "Signed in with Google successfully!" };
  } catch (error) {
    let message = "Google sign in failed.";
    if (error.code === 'auth/popup-blocked') message = "Popup was blocked. Please allow popups for this site.";
    if (error.code === 'auth/popup-closed-by-user') message = "Sign in cancelled.";
    
    return { success: false, error: message, code: error.code };
  }
};
    
    return { success: false, error: message, code: error.code };
  }
};

// Get Current User (synchronous)
export const getCurrentUser = () => {
  return auth.currentUser;
};

// Auth State Observer (realtime)
export const onAuthChange = (callback) => {
  return onAuthStateChanged(auth, (user) => {
    if (user) {
      callback({ 
        isAuthenticated: true, 
        user: {
          uid: user.uid,
          email: user.email,
          displayName: user.displayName,
          photoURL: user.photoURL,
          emailVerified: user.emailVerified,
          createdAt: user.metadata.creationTime,
          lastLoginAt: user.metadata.lastSignInTime
        }
      });
    } else {
      callback({ isAuthenticated: false, user: null });
    }
  });
};

// Check if user is authenticated
export const isAuthenticated = () => {
  return auth.currentUser !== null;
};

// Get ID Token (for backend verification)
export const getIdToken = async () => {
  const user = auth.currentUser;
  if (user) {
    return await user.getIdToken();
  }
  return null;
};

// Refresh ID Token
export const refreshToken = async () => {
  const user = auth.currentUser;
  if (user) {
    return await user.getIdToken(true);
  }
  return null;
};

// Export auth instance for advanced use
export { auth };
