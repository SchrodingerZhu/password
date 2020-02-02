use structopt::*;
#[derive(StructOpt, Debug, Eq, PartialEq)]
#[structopt(about = "the password keeper")]
pub(crate) enum Opt {
    #[structopt(about = "add a new password")]
    Add {
        #[structopt(short)]
        name: String,
    },
    #[structopt(about = "get the password")]
    Fetch {
        #[structopt(short)]
        name: String,
    },
    #[structopt(about = "remove the password")]
    Remove {
        #[structopt(short)]
        name: String,
    },
    #[structopt(about = "list all password names")]
    List,

    #[structopt(about = "generate a key pair if you do not have them")]
    GenKey {
        #[structopt(short, about = "path to the directory to contain the key")]
        path: String
    },

    #[structopt(about = "generate a new password and store")]
    GenPassword {
        #[structopt(short)]
        name: String
    }
}