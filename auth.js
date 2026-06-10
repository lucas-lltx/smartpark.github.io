// auth.js
// Complete Authentication Service for eParking System
// Supports: Email/Password and Google Sign In only

import { initializeApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";
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
    setPersistence,
    browserLocalPersistence,
    browserSessionPersistence,
    updateEmail,
    updatePassword,
    deleteUser,
    reauthenticateWithCredential,
    EmailAuthProvider
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";
import { 
    getFirestore, 
    doc, 
    getDoc, 
    setDoc, 
    updateDoc, 
    deleteDoc,
    serverTimestamp,
    arrayUnion,
    increment
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyAsz9T7h90cPCj8ZaLTrOCRgDhB0bJr1R8",
    authDomain: "eparking-75663.firebaseapp.com",
    projectId: "eparking-75663",
    storageBucket: "eparking-75663.firebasestorage.app",
    messagingSenderId: "199408130426",
    appId: "1:199408130426:web:8a55773fabb072d4ac1ec3"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// ==================== HELPER FUNCTIONS ====================

// Create user document in Firestore
export const createUserDocument = async (userId, userData) => {
    try {
        const userRef = doc(db, "users", userId);
        await setDoc(userRef, {
            ...userData,
            createdAt: userData.createdAt || serverTimestamp(),
            updatedAt: serverTimestamp(),
            parkingSessions: userData.parkingSessions || [],
            totalSpent: userData.totalSpent || 0,
            balance: userData.balance || 0,
            favoriteLocations: userData.favoriteLocations || []
        });
        return { success: true };
    } catch (error) {
        console.error("Create user document error:", error);
        return { success: false, error: error.message };
    }
};

// Get current user ID
export const getCurrentUserId = () => {
    return auth.currentUser ? auth.currentUser.uid : null;
};

// Get current user
export const getCurrentUser = () => {
    return auth.currentUser;
};

// Check if user is authenticated
export const isAuthenticated = () => {
    return auth.currentUser !== null;
};

// Get ID token for API calls
export const getIdToken = async () => {
    const user = auth.currentUser;
    if (user) {
        return await user.getIdToken();
    }
    return null;
};

// ==================== AUTHENTICATION SERVICES ====================

// Set auth persistence (local/session)
export const setAuthPersistence = async (type = 'local') => {
    try {
        const persistenceType = type === 'session' ? browserSessionPersistence : browserLocalPersistence;
        await setPersistence(auth, persistenceType);
        return { success: true, message: `Auth persistence set to ${type}` };
    } catch (error) {
        console.error("Persistence error:", error);
        return { success: false, error: error.message };
    }
};

// Email/Password Sign Up
export const signUp = async (email, password, displayName = null, phoneNumber = null) => {
    try {
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        
        // Update profile if display name provided
        if (displayName) {
            await updateProfile(user, { displayName });
        }
        
        // Send email verification
        await sendEmailVerification(user);
        
        // Create user document in Firestore
        await createUserDocument(user.uid, {
            email: user.email,
            displayName: displayName || user.email.split('@')[0],
            phoneNumber: phoneNumber || '',
            createdAt: serverTimestamp(),
            emailVerified: false,
            parkingSessions: [],
            totalSpent: 0,
            balance: 0,
            favoriteLocations: []
        });
        
        return { 
            success: true, 
            user: {
                uid: user.uid,
                email: user.email,
                displayName: user.displayName || user.email.split('@')[0],
                emailVerified: user.emailVerified
            }, 
            message: "Account created successfully! Please verify your email." 
        };
    } catch (error) {
        console.error("Sign up error:", error);
        let message = "Sign up failed";
        switch (error.code) {
            case 'auth/email-already-in-use':
                message = "Email already in use. Please use a different email or login.";
                break;
            case 'auth/invalid-email':
                message = "Invalid email address format.";
                break;
            case 'auth/weak-password':
                message = "Password should be at least 6 characters.";
                break;
            case 'auth/operation-not-allowed':
                message = "Email/password accounts are not enabled. Please contact support.";
                break;
            default:
                message = error.message;
        }
        return { success: false, error: message, code: error.code };
    }
};

// Email/Password Sign In
export const signIn = async (email, password) => {
    try {
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        
        // Optional: Check if email is verified (can be removed if not required)
        if (!user.emailVerified) {
            await signOut(auth);
            return { 
                success: false, 
                error: "Please verify your email before signing in. Check your inbox for verification link.",
                requiresVerification: true
            };
        }
        
        // Update last login in Firestore
        const userRef = doc(db, "users", user.uid);
        await updateDoc(userRef, {
            lastLoginAt: serverTimestamp(),
            lastLoginEmail: user.email
        });
        
        return { 
            success: true, 
            user: {
                uid: user.uid,
                email: user.email,
                displayName: user.displayName,
                photoURL: user.photoURL,
                emailVerified: user.emailVerified
            }, 
            message: "Signed in successfully!" 
        };
    } catch (error) {
        console.error("Sign in error:", error);
        let message = "Invalid email or password";
        switch (error.code) {
            case 'auth/user-not-found':
                message = "No account found with this email. Please sign up first.";
                break;
            case 'auth/wrong-password':
                message = "Incorrect password. Please try again.";
                break;
            case 'auth/too-many-requests':
                message = "Too many failed attempts. Please try again later.";
                break;
            case 'auth/user-disabled':
                message = "This account has been disabled. Please contact support.";
                break;
            case 'auth/invalid-email':
                message = "Invalid email address format.";
                break;
            default:
                message = error.message;
        }
        return { success: false, error: message, code: error.code };
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
        
        // Check if user exists in Firestore, if not create
        const userRef = doc(db, "users", user.uid);
        const userSnap = await getDoc(userRef);
        
        if (!userSnap.exists()) {
            await createUserDocument(user.uid, {
                email: user.email,
                displayName: user.displayName || user.email.split('@')[0],
                photoURL: user.photoURL || '',
                createdAt: serverTimestamp(),
                emailVerified: user.emailVerified,
                parkingSessions: [],
                totalSpent: 0,
                balance: 0,
                favoriteLocations: []
            });
        } else {
            // Update last login
            await updateDoc(userRef, {
                lastLoginAt: serverTimestamp(),
                lastLoginMethod: 'google'
            });
        }
        
        return { 
            success: true, 
            user: {
                uid: user.uid,
                email: user.email,
                displayName: user.displayName,
                photoURL: user.photoURL,
                emailVerified: user.emailVerified
            }, 
            message: "Signed in with Google successfully!" 
        };
    } catch (error) {
        console.error("Google sign in error:", error);
        let message = "Google sign in failed";
        if (error.code === 'auth/popup-blocked') {
            message = "Popup was blocked. Please allow popups for this site and try again.";
        } else if (error.code === 'auth/popup-closed-by-user') {
            message = "Sign in cancelled. Please try again.";
        } else if (error.code === 'auth/account-exists-with-different-credential') {
            message = "An account already exists with the same email address but different sign-in method. Please sign in using your email and password.";
        }
        return { success: false, error: message, code: error.code };
    }
};

// Sign Out
export const logOut = async () => {
    try {
        await signOut(auth);
        return { success: true, message: "Signed out successfully!" };
    } catch (error) {
        console.error("Logout error:", error);
        return { success: false, error: error.message };
    }
};

// Password Reset
export const resetPassword = async (email) => {
    try {
        await sendPasswordResetEmail(auth, email);
        return { 
            success: true, 
            message: "Password reset email sent! Please check your inbox and follow the instructions." 
        };
    } catch (error) {
        console.error("Password reset error:", error);
        let message = "Failed to send reset email";
        if (error.code === 'auth/user-not-found') {
            message = "No account found with this email address.";
        } else if (error.code === 'auth/invalid-email') {
            message = "Invalid email address format.";
        }
        return { success: false, error: message, code: error.code };
    }
};

// Resend Verification Email
export const resendVerificationEmail = async () => {
    try {
        const user = auth.currentUser;
        if (!user) {
            return { success: false, error: "No user logged in" };
        }
        await sendEmailVerification(user);
        return { success: true, message: "Verification email sent! Please check your inbox." };
    } catch (error) {
        console.error("Resend verification error:", error);
        return { success: false, error: error.message };
    }
};

// Update User Profile
export const updateUserProfile = async (displayName = null, photoURL = null) => {
    try {
        const user = auth.currentUser;
        if (!user) {
            return { success: false, error: "No user logged in" };
        }
        
        const updates = {};
        if (displayName) updates.displayName = displayName;
        if (photoURL) updates.photoURL = photoURL;
        
        if (Object.keys(updates).length > 0) {
            await updateProfile(user, updates);
        }
        
        // Update Firestore
        await updateDoc(doc(db, "users", user.uid), {
            ...updates,
            updatedAt: serverTimestamp()
        });
        
        return { 
            success: true, 
            user: {
                uid: user.uid,
                email: user.email,
                displayName: user.displayName,
                photoURL: user.photoURL
            }, 
            message: "Profile updated successfully!" 
        };
    } catch (error) {
        console.error("Update profile error:", error);
        return { success: false, error: error.message };
    }
};

// Update Email (requires re-authentication)
export const updateUserEmail = async (newEmail, password) => {
    try {
        const user = auth.currentUser;
        if (!user) {
            return { success: false, error: "No user logged in" };
        }
        
        // Re-authenticate user before changing email
        const credential = EmailAuthProvider.credential(user.email, password);
        await reauthenticateWithCredential(user, credential);
        
        await updateEmail(user, newEmail);
        await sendEmailVerification(user); // Send verification to new email
        
        // Update Firestore
        await updateDoc(doc(db, "users", user.uid), {
            email: newEmail,
            emailVerified: false,
            updatedAt: serverTimestamp()
        });
        
        return { 
            success: true, 
            message: "Email updated! Please verify your new email address." 
        };
    } catch (error) {
        console.error("Update email error:", error);
        let message = "Failed to update email";
        if (error.code === 'auth/wrong-password') {
            message = "Incorrect password";
        } else if (error.code === 'auth/email-already-in-use') {
            message = "Email already in use by another account";
        } else if (error.code === 'auth/requires-recent-login') {
            message = "Please log out and log in again before changing email";
        }
        return { success: false, error: message };
    }
};

// Update Password (requires re-authentication)
export const updateUserPassword = async (currentPassword, newPassword) => {
    try {
        const user = auth.currentUser;
        if (!user) {
            return { success: false, error: "No user logged in" };
        }
        
        // Re-authenticate user before changing password
        const credential = EmailAuthProvider.credential(user.email, currentPassword);
        await reauthenticateWithCredential(user, credential);
        
        await updatePassword(user, newPassword);
        
        return { 
            success: true, 
            message: "Password updated successfully! Please use your new password next time you log in." 
        };
    } catch (error) {
        console.error("Update password error:", error);
        let message = "Failed to update password";
        if (error.code === 'auth/wrong-password') {
            message = "Current password is incorrect";
        } else if (error.code === 'auth/weak-password') {
            message = "New password is too weak. Please use at least 6 characters.";
        } else if (error.code === 'auth/requires-recent-login') {
            message = "Please log out and log in again before changing password";
        }
        return { success: false, error: message };
    }
};

// Delete User Account (requires re-authentication)
export const deleteUserAccount = async (password) => {
    try {
        const user = auth.currentUser;
        if (!user) {
            return { success: false, error: "No user logged in" };
        }
        
        // Re-authenticate user before deleting account
        const credential = EmailAuthProvider.credential(user.email, password);
        await reauthenticateWithCredential(user, credential);
        
        // Delete user document from Firestore
        await deleteDoc(doc(db, "users", user.uid));
        
        // Delete user from Auth
        await deleteUser(user);
        
        return { 
            success: true, 
            message: "Account deleted successfully! We're sad to see you go." 
        };
    } catch (error) {
        console.error("Delete account error:", error);
        let message = "Failed to delete account";
        if (error.code === 'auth/wrong-password') {
            message = "Incorrect password";
        } else if (error.code === 'auth/requires-recent-login') {
            message = "Please log out and log in again before deleting account";
        }
        return { success: false, error: message };
    }
};

// ==================== USER DATA MANAGEMENT ====================

// Get user data from Firestore
export const getUserData = async (userId = null) => {
    try {
        const uid = userId || getCurrentUserId();
        if (!uid) {
            return { success: false, error: "No user logged in" };
        }
        
        const userRef = doc(db, "users", uid);
        const userSnap = await getDoc(userRef);
        
        if (userSnap.exists()) {
            return { success: true, data: userSnap.data() };
        } else {
            return { success: false, error: "User data not found" };
        }
    } catch (error) {
        console.error("Get user data error:", error);
        return { success: false, error: error.message };
    }
};

// Update user data in Firestore
export const updateUserData = async (data) => {
    try {
        const uid = getCurrentUserId();
        if (!uid) {
            return { success: false, error: "No user logged in" };
        }
        
        const userRef = doc(db, "users", uid);
        await updateDoc(userRef, {
            ...data,
            updatedAt: serverTimestamp()
        });
        
        return { success: true, message: "User data updated successfully" };
    } catch (error) {
        console.error("Update user data error:", error);
        return { success: false, error: error.message };
    }
};

// Update user balance
export const updateUserBalance = async (amount, operation = 'add') => {
    try {
        const uid = getCurrentUserId();
        if (!uid) {
            return { success: false, error: "No user logged in" };
        }
        
        const userRef = doc(db, "users", uid);
        const incrementValue = operation === 'add' ? amount : -amount;
        
        await updateDoc(userRef, {
            balance: increment(incrementValue),
            updatedAt: serverTimestamp()
        });
        
        return { success: true, message: "Balance updated successfully" };
    } catch (error) {
        console.error("Update balance error:", error);
        return { success: false, error: error.message };
    }
};

// Add parking session
export const addParkingSession = async (sessionData) => {
    try {
        const uid = getCurrentUserId();
        if (!uid) {
            return { success: false, error: "No user logged in" };
        }
        
        const userRef = doc(db, "users", uid);
        const session = {
            ...sessionData,
            id: Date.now().toString(),
            startTime: serverTimestamp(),
            status: 'active'
        };
        
        await updateDoc(userRef, {
            parkingSessions: arrayUnion(session),
            updatedAt: serverTimestamp()
        });
        
        return { success: true, session: session };
    } catch (error) {
        console.error("Add parking session error:", error);
        return { success: false, error: error.message };
    }
};

// ==================== AUTH STATE OBSERVER ====================

// Auth state observer (realtime)
export const onAuthChange = (callback) => {
    return onAuthStateChanged(auth, async (user) => {
        if (user) {
            // Get additional user data from Firestore
            const userDataResult = await getUserData(user.uid);
            callback({ 
                isAuthenticated: true, 
                user: {
                    uid: user.uid,
                    email: user.email,
                    displayName: user.displayName,
                    photoURL: user.photoURL,
                    emailVerified: user.emailVerified,
                    ...(userDataResult.success ? userDataResult.data : {})
                }
            });
        } else {
            callback({ isAuthenticated: false, user: null });
        }
    });
};

// ==================== EXPORTS ====================

// Export initialized instances
export { auth, db, app };

// Default export for convenience
export default {
    // Auth methods
    signUp,
    signIn,
    signInWithGoogle,
    logOut,
    resetPassword,
    resendVerificationEmail,
    updateUserProfile,
    updateUserEmail,
    updateUserPassword,
    deleteUserAccount,
    setAuthPersistence,
    
    // User methods
    getUserData,
    updateUserData,
    updateUserBalance,
    addParkingSession,
    
    // Helper methods
    getCurrentUser,
    getCurrentUserId,
    isAuthenticated,
    getIdToken,
    onAuthChange,
    
    // Create user document
    createUserDocument,
    
    // Instances
    auth,
    db,
    app
};
