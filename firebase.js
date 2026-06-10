import { initializeApp } from "https://www.gstatic.com/firebasejs/12.0.0/firebase-app.js";

import { getAuth } from "https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";

import { getFirestore } from "https://www.gstatic.com/firebasejs/12.0.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyAsz9T7h90cPCj8ZaLTrOCRgDhB0bJr1R8",
  authDomain: "eparking-75663.firebaseapp.com",
  projectId: "eparking-75663",
  storageBucket: "eparking-75663.firebasestorage.app",
  messagingSenderId: "199408130426",
  appId: "1:199408130426:web:8a55773fabb072d4ac1ec3",
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
