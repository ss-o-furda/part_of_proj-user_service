import React, {useState} from "react";
import './loginform.css'
import {toast, ToastContainer} from 'react-toastify';
import 'react-toastify/dist/ReactToastify.min.css';
const axios = require('axios');

const LoginForm = () => {

    const validateValue = (value, rule) => {
        return rule.test(value);
    };
    const disableSpaces = event => {
        if (event.keyCode === 32) {
            event.preventDefault();
        }
    };

    const [state, setState] = useState({
        userEmail: '',
        isUserEmailValid: false,
        userPassword: '',
        isUserPasswordValid: false
    });

    const handleUserEmailChange = event => {
        const currentValue = event.target.value;
        const isUserEmailValid = validateValue(currentValue, /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
        setState(prevState => ({
            ...prevState, userEmail: currentValue, isUserEmailValid: isUserEmailValid
        }))
    };

    const handlePasswordChange = event => {
        const currentValue = event.target.value;
        setState(prevState => ({
            ...prevState, userPassword: currentValue
        }))
    };

    const handleSendData = event => {
        event.preventDefault();
        const url = 'http://127.0.0.1:5000/login';
        const config = {
            body: JSON.stringify({

            }),

            cache: 'no-cache',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            withCredentials: true
        };
        axios({
            method: 'POST',
            url: url,
            data: {user_email: state.userEmail,
                user_password: state.userPassword}

        }).then(function (response) {
            alert(response.data);
        }).catch(function (error) {
            if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      alert(error.response.data);
      alert(error.response.status);
      alert(error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
      // http.ClientRequest in node.js
      alert(error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      alert('Error', error.message);
    }
            alert(error.config);
        });
    }

    return (
        <div className="container h-75">
            <div className="row h-100 align-items-center">
                <div className="col-2"/>
                <div className="col-8">
                    <form onSubmit={handleSendData}>
                        <h3>Login to your account</h3>
                        <div className="form-group">
                            <label htmlFor="exampleInputEmail1">Email address</label>
                            <input type="email" className="form-control"
                                   aria-describedby="emailHelp"
                                   placeholder="Enter email"
                                   onChange={handleUserEmailChange}
                                   onKeyDown={disableSpaces}/>
                            <small id="emailHelp" className="form-text text-muted">We'll never share your email with
                                anyone
                                else.</small>
                        </div>
                        <div className="form-group">
                            <label htmlFor="exampleInputPassword1">Password</label>
                            <input type="password" className="form-control"
                                   placeholder="Password" onChange={handlePasswordChange}
                                   onKeyDown={disableSpaces}/>
                        </div>
                        <button type="submit" className="btn btn-primary">Login</button>
                        <ToastContainer/>
                    </form>
                </div>
                <div className="col-2"/>
            </div>
        </div>
    )
};

export default LoginForm;