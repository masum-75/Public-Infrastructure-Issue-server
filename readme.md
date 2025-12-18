# Public Infrastructure Issue Server 

The backend engine for the Public Infrastructure Issue Reporting System. This server handles authentication, issue reporting, tracking, payment processing for priority boosting, and role-based access control.

###  [Live API Link](https://public-infrastructure-issue-server.vercel.app/)



##  Features

* **Secure Authentication**: JWT-based authentication for citizens, staff, and admins.
* **Issue Management**: Full CRUD operations for reporting and managing public infrastructure problems.
* **Role-Based Access Control **: Distinct permissions for Citizens, Staff members, and System Administrators.
* **Real-time Tracking**: Timeline logging for status updates (Pending → In-Progress → Resolved).
* **Priority Boosting**: Integrated Stripe payment gateway for issue priority escalation.
* **Optimized Queries**: Advanced filtering, searching, and pagination powered by MongoDB and TanStack Query logic.

##  Tech Stack

* **Runtime**: Node.js
* **Framework**: Express.js
* **Database**: MongoDB (with Mongoose/Native Driver)
* **Security**: JWT, bcryptjs, CORS, Helmet
* **Deployment**: Vercel