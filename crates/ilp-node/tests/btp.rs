use futures::{future::join_all, Future};
use ilp_node::{random_secret, InterledgerNode};
use interledger::{packet::Address, service::Username};
use serde_json::json;
use std::str::FromStr;
use tokio::runtime::Builder as RuntimeBuilder;

mod redis_helpers;
use redis_helpers::*;

mod test_helpers;
use test_helpers::*;

#[test]
fn two_nodes_btp() {
    // Nodes 1 and 2 are peers, Node 2 is the parent of Node 2
    let _ = env_logger::try_init();
    let context = TestContext::new();

    // Each node will use its own DB within the redis instance
    let mut connection_info1 = context.get_client_connection_info();
    connection_info1.db = 1;
    let mut connection_info2 = context.get_client_connection_info();
    connection_info2.db = 2;

    let node_a_http = get_open_port(Some(3010));
    let node_a_settlement = get_open_port(Some(3011));
    let node_b_http = get_open_port(Some(3020));
    let node_b_settlement = get_open_port(Some(3021));

    let mut runtime = RuntimeBuilder::new()
        .panic_handler(|_| panic!("Tokio worker panicked"))
        .build()
        .unwrap();

    let alice_on_a = json!({
        "username": "alice_on_a",
        "asset_code": "XYZ",
        "asset_scale": 9,
        "ilp_over_http_incoming_token" : "default account holder",
    });
    let b_on_a = json!({
        "username": "b_on_a",
        "asset_code": "XYZ",
        "asset_scale": 9,
        "ilp_over_btp_url": format!("btp+ws://localhost:{}/ilp/btp", node_b_http),
        "ilp_over_btp_outgoing_token" : "a_on_b:token",
        "routing_relation": "Parent",
    });

    let a_on_b = json!({
        "username": "a_on_b",
        "asset_code": "XYZ",
        "asset_scale": 9,
        // TODO make sure this field can exactly match the outgoing token on the other side
        "ilp_over_btp_incoming_token" : "token",
        "routing_relation": "Child",
    });
    let bob_on_b = json!({
        "username": "bob_on_b",
        "asset_code": "XYZ",
        "asset_scale": 9,
        "ilp_over_http_incoming_token" : "default account holder",
    });

    let node_a = InterledgerNode {
        ilp_address: None,
        default_spsp_account: None,
        admin_auth_token: "admin".to_string(),
        redis_connection: connection_info1,
        http_bind_address: ([127, 0, 0, 1], node_a_http).into(),
        settlement_api_bind_address: ([127, 0, 0, 1], node_a_settlement).into(),
        secret_seed: random_secret(),
        route_broadcast_interval: Some(200),
        exchange_rate_poll_interval: 60000,
        exchange_rate_provider: None,
        exchange_rate_spread: 0.0,
    };

    let node_b = InterledgerNode {
        ilp_address: Some(Address::from_str("example.parent").unwrap()),
        default_spsp_account: Some(Username::from_str("bob_on_b").unwrap()),
        admin_auth_token: "admin".to_string(),
        redis_connection: connection_info2,
        http_bind_address: ([127, 0, 0, 1], node_b_http).into(),
        settlement_api_bind_address: ([127, 0, 0, 1], node_b_settlement).into(),
        secret_seed: random_secret(),
        route_broadcast_interval: Some(200),
        exchange_rate_poll_interval: 60000,
        exchange_rate_provider: None,
        exchange_rate_spread: 0.0,
    };

    let alice_fut = join_all(vec![
        create_account_on_node(node_a_http, alice_on_a, "admin"),
        create_account_on_node(node_a_http, b_on_a, "admin"),
    ]);

    runtime.spawn(node_a.serve());

    let bob_fut = join_all(vec![
        create_account_on_node(node_b_http, a_on_b, "admin"),
        create_account_on_node(node_b_http, bob_on_b, "admin"),
    ]);

    runtime.spawn(node_b.serve());

    runtime
        .block_on(
            // Wait for the nodes to spin up
            delay(500)
                .map_err(|_| panic!("Something strange happened"))
                .and_then(move |_| {
                    bob_fut
                        .and_then(|_| alice_fut)
                        .and_then(|_| delay(500).map_err(|_| panic!("delay error")))
                })
                .and_then(move |_| {
                    let send_1_to_2 = send_money_to_username(
                        node_a_http,
                        node_b_http,
                        1000,
                        "bob_on_b",
                        "alice_on_a",
                        "default account holder",
                    );
                    let send_2_to_1 = send_money_to_username(
                        node_b_http,
                        node_a_http,
                        2000,
                        "alice_on_a",
                        "bob_on_b",
                        "default account holder",
                    );

                    let get_balances = move || {
                        futures::future::join_all(vec![
                            get_balance("alice_on_a", node_a_http, "admin"),
                            get_balance("bob_on_b", node_b_http, "admin"),
                        ])
                    };

                    send_1_to_2
                        .map_err(|err| {
                            eprintln!("Error sending from node 1 to node 2: {:?}", err);
                            err
                        })
                        .and_then(move |_| {
                            get_balances().and_then(move |ret| {
                                assert_eq!(ret[0], -1000);
                                assert_eq!(ret[1], 1000);
                                Ok(())
                            })
                        })
                        .and_then(move |_| {
                            send_2_to_1.map_err(|err| {
                                eprintln!("Error sending from node 2 to node 1: {:?}", err);
                                err
                            })
                        })
                        .and_then(move |_| {
                            get_balances().and_then(move |ret| {
                                assert_eq!(ret[0], 1000);
                                assert_eq!(ret[1], -1000);
                                Ok(())
                            })
                        })
                }),
        )
        .unwrap();
}
