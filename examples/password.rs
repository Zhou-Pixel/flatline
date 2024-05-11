use flatline::handshake::Config;
use flatline::session::Session;
use flatline::session::Userauth;
use tokio::net::TcpStream;

include!("./user.conf");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let socket = TcpStream::connect(HOST).await.unwrap();
    let config = Config::deafult_with_behavior();
    let session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password(USERNAME, PASSWORD).await.unwrap();

    assert!(matches!(status, Userauth::Success));

    session.disconnect_default().await.unwrap();
}
