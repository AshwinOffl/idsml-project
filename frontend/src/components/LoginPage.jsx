import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const Login = () => {
    const [userId, setUserId] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleLogin = async () => {
        try {
            const response = await fetch('http://localhost:5000/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });
            const data = await response.json();
            if (data.token) {
                localStorage.setItem('token', data.token);
                const decoded = jwt_decode(data.token);
                if (decoded.role === 'admin') {
                    navigate('/admin-dashboard');  // Redirect to admin dashboard
                } else {
                    navigate('/user-dashboard');  // Redirect to user dashboard
                }
            } else {
                setError('Login failed');
            }
        } catch (error) {
            setError('An error occurred during login');
        }
    };

    return (
        <div>
            <input
                type="text"
                placeholder="Enter User ID"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
            />
            <button onClick={handleLogin}>Login</button>
            {error && <div>{error}</div>}
        </div>
    );
};

export default Login;
