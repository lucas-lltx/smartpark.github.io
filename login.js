import { auth, db } from "./firebase.js";
import { signInWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";
import { doc, getDoc } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

document.getElementById("loginForm").addEventListener("submit", async (e)=>{
    e.preventDefault();

    const email = email.value;
    const password = password.value;

    try{
        const userCred = await signInWithEmailAndPassword(auth,email,password);

        const uid = userCred.user.uid;

        const snap = await getDoc(doc(db,"users",uid));

        const data = snap.data();

        if(data.role === "staff"){
            window.location.href = "staff.html";
        }else{
            window.location.href = "home.html";
        }

    }catch(err){
        alert(err.message);
    }
});
