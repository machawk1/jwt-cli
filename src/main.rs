// Welcome to my annotated jwt-cli rust file.
// Below are the crates (external dependencies) I'm bringing in and will be using.
// Similar to ES6 modules, you can alias the import to something more typeable.
// The `#[macro_use]` allows me to use macros from the crates.
#[macro_use]
extern crate clap;
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;
extern crate term_painter;

// Here we setup some import paths to make references later on much easier.
// In the case of BTreeMap, I can use BTreeMap::new(); later, rather than
// std::collection::BTreeMap::new();
use std::collections::BTreeMap;
use clap::{App, Arg, ArgMatches, SubCommand};
use jwt::{encode, decode, Algorithm, Header, TokenData};
use jwt::errors::Error;
use rustc_serialize::json;
use term_painter::ToStyle;
use term_painter::Color::*;
use term_painter::Attr::*;

// derive(Debug) tells the rust compiler to automatically add methods to log this to the console.
#[derive(Debug)]
struct PayloadItem(String, String);

// Same thing here, but also telling rustc_serialize to add some of it's own methods automatically.
#[derive(Debug, RustcEncodable, RustcDecodable)]
struct Payload(BTreeMap<String, String>);

// arg_enum! is a macro from the `clap` crate which allows this to be used to validate incoming
// data from the cli. e.g. Only these values are allowed for a parameter.
arg_enum!{
    enum SupportedAlgorithms {
        HS256,
        HS384,
        HS512
    }
}

arg_enum!{
    enum SupportedTypes {
        JWT
    }
}

// `impl` is a keyword to add methods to a struct.
// This helps to group functions used for instantializing or otherwise working with a specific
// struct.
impl PayloadItem {
    // A really great thing about Rust is it's concept of optional data. Here, we take in a string,
    // but sometimes that string will be `null` and sometimes it will have a value. Having the
    // concept of an optional lets the compiler know that sometimes the value won't exist, thereby
    // forcing you to handle the case when something isn't present.
    // No more `undefined isn't a function`, etc!
    fn from_string(val: Option<&str>) -> Option<PayloadItem> {
        if val.is_some() {
            // This calls the method we added below in the same `impl PayloadItem` block.
            // Additionally, since we need to return an `Option` type, we wrap the value in a
            // `Some` and return it. If there's no value, we return `None`.
            Some(PayloadItem::split_payload_item(val.unwrap()))
        } else {
            None
        }
    }

    // Here, we always expect a value for `p`, so no need to add the `Option` wrapper.
    fn split_payload_item(p: &str) -> PayloadItem {
        let split: Vec<&str> = p.split('=').collect();

        PayloadItem(split[0].to_string(), split[1].to_string())
    }
}

impl Payload {
    // `Vec` is a type of array. The main difference is that it can grow in size, or its size won't
    // be known when the program compiles. In Rust, arrays are normall a fixed size, and cannot
    // change. Because the stuff inside a JWT payload can differ, we need a dynamically sized array.
    fn from_payloads(payloads: Vec<PayloadItem>) -> Payload {
        let mut payload = BTreeMap::new();

        for PayloadItem(k, v) in payloads {
            payload.insert(k, v);
        }

        Payload(payload)
    }
}

impl SupportedAlgorithms {
    fn from_string(alg: &str) -> SupportedAlgorithms {
        // `match` blocks are essentially `switch` or `case` statements. They match a given value
        // against a pattern.
        // The really cool part about Rust's `match` is that it's an expression, so you can return
        // matches and assign them to a variable or return them from a function!
        match alg {
            "HS256" => SupportedAlgorithms::HS256,
            "HS384" => SupportedAlgorithms::HS384,
            "HS512" => SupportedAlgorithms::HS512,
            _ => SupportedAlgorithms::HS256,
        }
    }
}

// The `'a` and `'b` here are lifetime specifiers. I don't understand them that well and take stabs
// at them until the compiler doesn't complain.
fn config_options<'a, 'b>() -> App<'a, 'b> {
    // If you scroll back up to the `use` section, you'll see we're bringing in `App`. This allows
    // this to use `App::new` rather than `clap::App::new`.
    // This is quite long, but is the config for the cli commands. To see these in action, start
    // by typing `jwt-cli help`.
    App::new("jwt-cli")
        .about("Encode and decode JWTs from the command line")
        .version(crate_version!())
        .author(crate_authors!())
        .subcommand(SubCommand::with_name("generate")
            .about("Encode new JWTs")
            .arg(Arg::with_name("algorithm")
                .help("the algorithm to use for signing the JWT")
                .takes_value(true)
                .long("alg")
                .short("A")
                .possible_values(&SupportedAlgorithms::variants())
                .default_value("HS256"))
            .arg(Arg::with_name("kid")
                .help("the kid to place in the header")
                .takes_value(true)
                .long("kid")
                .short("k"))
            .arg(Arg::with_name("type")
                .help("the type of token being generated")
                .takes_value(true)
                .long("typ")
                .short("t")
                .possible_values(&SupportedTypes::variants()))
            .arg(Arg::with_name("payload")
                .help("a key=value pair to add to the payload")
                .multiple(true)
                .takes_value(true)
                .long("payload")
                .short("p")
                .validator(is_payload_item))
            .arg(Arg::with_name("expires")
                .help("the time the token should expire, in seconds")
                .takes_value(true)
                .long("expires")
                .short("e")
                .validator(is_num))
            .arg(Arg::with_name("issuer")
                .help("the issuer of the token")
                .takes_value(true)
                .long("iss")
                .short("i"))
            .arg(Arg::with_name("subject")
                .help("the subject of the token")
                .takes_value(true)
                .long("sub")
                .short("s"))
            .arg(Arg::with_name("audience")
                .help("the audience of the token")
                .takes_value(true)
                .long("aud")
                .short("a")
                .requires("principal"))
            .arg(Arg::with_name("principal")
                .help("the principal of the token")
                .takes_value(true)
                .long("prn")
                .short("P")
                .requires("audience"))
            .arg(Arg::with_name("not_before")
                .help("the time the JWT should become valid, in seconds")
                .takes_value(true)
                .long("nbf")
                .short("n"))
            .arg(Arg::with_name("secret")
                .help("the secret to sign the JWT with")
                .takes_value(true)
                .long("secret")
                .short("S")
                .required(true)))
        .subcommand(SubCommand::with_name("decode")
            .about("Decode a JWT")
            .arg(Arg::with_name("jwt")
                .help("the jwt to decode")
                .index(1)
                .required(true))
            .arg(Arg::with_name("algorithm")
                .help("the algorithm to use for signing the JWT")
                .takes_value(true)
                .long("alg")
                .short("A")
                .possible_values(&SupportedAlgorithms::variants())
                .required(true))
            .arg(Arg::with_name("secret")
                .help("the secret to sign the JWT with")
                .takes_value(true)
                .long("secret")
                .short("S")
                .required(true)))
}

// These are validators used to validate data coming in through the command line arguments.
// This returns a `Result` type. Similar to `Option`, it lets the Rust compiler know that this
// function can return an error or some data, forcing us to handle both cases.
fn is_num(val: String) -> Result<(), String> {
    // This is basically parseInt('2', 10);
    let parse_result = i32::from_str_radix(&val, 10);

    // Here we're matching against a `Result` type. `Result`s are either `Ok` or `Err`, each with
    // A corresponding value, which we can destructure in the `match` block.
    match parse_result {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("expires must be an integer")),
    }
}

fn is_payload_item(val: String) -> Result<(), String> {
    let split: Vec<&str> = val.split('=').collect();

    // Just like `switch` or `case`, you can match on nearly anything. Here, this is checking the
    // length of the `Vec` array called `split`.
    match split.len() {
        2 => Ok(()),
        _ => Err(String::from("payloads must have a key and value in the form key=value")),
    }
}

// The argument `matches` here has a value of `&ArgMatches`. What this tells the compiler is that
// the function takes in a _reference_ to an `ArgMatches` type. Practically, this means that this
// function can view the value of `matches`, but it can't modify it. It also means that the
// value of `matches` cannot be viewed or modified by any other function, guaranteeing that we get
// an accurate value and that code run after this function can still view the contents of `matches`.
fn warn_unsupported(matches: &ArgMatches) {
    // Because we only care if there is a value for the `type` argument, we can use `is_some()`,
    // which returns a boolean if the value is `Some`, but false if it's `None`.
    if matches.value_of("type").is_some() {
        println!("Sorry, `typ` isn't supported quite yet!");
    }
}

fn translate_algorithm(alg: SupportedAlgorithms) -> Algorithm {
    match alg {
        SupportedAlgorithms::HS256 => Algorithm::HS256,
        SupportedAlgorithms::HS384 => Algorithm::HS384,
        SupportedAlgorithms::HS512 => Algorithm::HS512,
    }
}

fn create_header(alg: &Algorithm, kid: Option<&str>) -> Header {
    let mut header = Header::new(alg.clone());

    header.kid = kid.map(|k| k.to_string());

    header
}

// This function doesn't return a value, so we can omit the `-> Type` part of the function
// signature. We could have optionally written `-> ()`, but that's more work.
fn generate_token(matches: &ArgMatches) {
    let algorithm =
        translate_algorithm(SupportedAlgorithms::from_string(matches.value_of("algorithm")
            .unwrap()));
    let kid = matches.value_of("kid");
    let header = create_header(&algorithm, kid);
    // In this case, the compiler can't infer by itself what the type of `custom_payloads` will be
    // after the expression has run. To assist the compiler (and because it helps _us_ so much
    // more) we tell it what the value should be. In this case, the eventual value for this
    // variable will be an `Vec` (changeable array) with a bunch of `PayloadItem`s for values.
    // The opteration may also return nothing, so it's wrapped in an `Option`.
    let custom_payloads: Option<Vec<Option<PayloadItem>>> = matches.values_of("payload")
        // Here we have a closure. This is similar to an anonymous function in Javascript, Lambda
        // in python, block in ruby, etc.
        .map(|maybe_payloads| {
            maybe_payloads.map(|p| PayloadItem::from_string(Some(p)))
                .collect()
        });
    let expires = PayloadItem::from_string(matches.value_of("expires"));
    let issuer = PayloadItem::from_string(matches.value_of("issuer"));
    let subject = PayloadItem::from_string(matches.value_of("subject"));
    let audience = PayloadItem::from_string(matches.value_of("audience"));
    let principal = PayloadItem::from_string(matches.value_of("principal"));
    let not_before = PayloadItem::from_string(matches.value_of("not_before"));
    // Ah, the `mut` keyword. While Rust is billed as a functional language, sometimes you just
    // gotta mutate because the available methods mutate. `mut` tells the compiler that the value
    // of the variable can change. Without `mut`, any attempt to alter the value of a variable
    // will result in the compiler yelling at you.
    let mut maybe_payloads: Vec<Option<PayloadItem>> = vec![expires, issuer, subject, audience,
                                                            principal, not_before];

    // Same concept here, but instead we're creating a mutable _reference_ to a value.
    maybe_payloads.append(&mut custom_payloads.unwrap_or(vec![]));

    let payloads = maybe_payloads.into_iter().filter(|p| p.is_some()).map(|p| p.unwrap()).collect();
    let payload = Payload::from_payloads(payloads);
    // Here is an important method `unwrap`. It's defined on the `Option` type. What it does is
    // tells the compiler that there will _always_ be a value (never `None`). Normally, this is a
    // bad idea. It works in this case, however, because `clap` has mandated that the `secret` is
    // required. If the user doesn't pass a value, the app immediately fails.
    let secret = matches.value_of("secret").unwrap().as_bytes();
    let token = encode(header, &payload, secret.as_ref());

    match token {
        // Here you can see the awesome destructuring. We can get an `Ok` result from the `encode`
        // function, and the value inside that `Ok` will be the JWT we created. So, we assign the
        // value of that jwt to a variable `jwt` that we can use later (which we do!).
        Ok(jwt) => {
            println!("Here's your token:");
            println!("{}", jwt);
        }
        // Same concept for `Err` values in a `Result` type.
        Err(err) => {
            println!("Something went awry creating the jwt. Here's the error:");
            println!("{}", err);
        }
    }

}

fn decode_token(matches: &ArgMatches) {
    let algorithm =
        translate_algorithm(SupportedAlgorithms::from_string(matches.value_of("algorithm")
            .unwrap()));
    let secret = matches.value_of("secret").unwrap().as_bytes();
    let jwt = matches.value_of("jwt").unwrap().to_string();
    let token = decode::<Payload>(&jwt, secret.as_ref(), algorithm);

    match token {
        // This is a pretty good example of how far you can destructure things in a `match` block.
        // Here, We deconstruct a `Struct` called `TokenData`, which has two keys: `header` and
        // `claims`. The `claims` value is an instance of a `Payload` struct, which we then
        // assign the value of _that_ to a variable called `claims`.
        Ok(TokenData { header, claims: Payload(claims) }) => {
            // Here we encode (into a string) and then decode it immediately into a type that
            // rustc_serialize understands. This allows the JSON object to be pretty printed to
            // the console without this tool having to implement a pretty printing function.
            let json_header = json::encode(&header).unwrap();
            let json_claims = json::encode(&claims).unwrap();
            let decoded_header = json::Json::from_str(&json_header).unwrap();
            let decoded_claims = json::Json::from_str(&json_claims).unwrap();

            println!("{}\n", Cyan.bold().paint("Looks like a valid JWT!"));
            println!("{}", Plain.bold().paint("Token header\n------------"));
            println!("{}\n", decoded_header.pretty());
            println!("{}", Plain.bold().paint("Token claims\n------------"));
            println!("{}", decoded_claims.pretty());
        }
        Err(err) => {
            // Another cool thing is that you can nest `match`es! Here we handle the case that
            // `decode` returns an error, and assign the error to a variable `err`. We then match
            // against the value of that error to get very specific to help the user debug.
            match err {
                Error::InvalidToken => println!("The JWT provided is invalid"),
                Error::InvalidSignature => println!("The JWT provided has an invalid signature"),
                Error::WrongAlgorithmHeader => {
                    println!("The JWT provided has a different signing algorithm than the one you \
                              provided")
                }
                // Here we have a catchall. If we get a anything else other than the first three
                // values (`_`), then we just don't do anything. We _have_ to account for these
                // cases because the return value of `matches.subcommand()` tells the compiler that
                // there are more possibilities than the first two. Even though it's not possible,
                // we still need to account for it.
                _ => println!("The JWT provided is invalid because {:?}", err),
            }
        }
    }
}

// `main` is the entry point for your app/lib/binary/whatever. This function gets run first, no
// matter what. Anything you want to do with your app starts here!
fn main() {
    let matches = config_options().get_matches();

    // Like we saw before, `match` can match and destructure anything, including tuples.
    match matches.subcommand() {
        // Here we're looking for a tuple where the first value is "generate", and the second
        // is a `Some` with a value we want to assign to a variable called `generate_matches`.
        ("generate", Some(generate_matches)) => {
            warn_unsupported(&generate_matches);
            generate_token(&generate_matches);
        }
        ("decode", Some(decode_matches)) => decode_token(&decode_matches),
        _ => (),
    }
}
