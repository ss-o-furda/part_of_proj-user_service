import React from 'react';
import NavBar from "./components/NavBar/NavBar";
import LoginForm from "./components/Forms/LoginForm/LoginForm";
import {Route} from 'react-router-dom';

function App() {
    return (
        <>
            <NavBar/>
            <Route path="/login" render={() => <LoginForm/>}/>
        </>
    )
}

export default App;
