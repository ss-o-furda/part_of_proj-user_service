import React from "react";

const NavBar = props => {

    return (
        <nav className="navbar navbar-light bg-light justify-content-between">
            <a className="navbar-brand" href='/'>TabGen</a>
            <ul className="nav justify-content-between">
                <li className="nav-item">
                    <a className="nav-link" href="/login">Login</a>
                </li>
                <li className="nav-item">
                    <a className="nav-link" href="/register">Register</a>
                </li>
            </ul>
        </nav>
    )
};

export default NavBar;