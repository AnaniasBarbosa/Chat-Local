const passport = require("passport")
const bcrypt = require("bcrypt")
const LocalStrategy = require("passport-local")
const GitHubStrategy = require("passport-github")
const { ObjectID } = require("mongodb")

const gitHubClientID = process.env.GITHUB_CLIENT_ID
const gitHubClientSecret = process.env.GITHUB_CLIENT_SECRET
const githubCallBackUrl = process.env.GITHUB_CLIENT_CALLBACKURL

module.exports = function (app, myDataBase) {
  passport.serializeUser((user, done) => {
    done(null, user._id)
  })
  passport.deserializeUser((id, done) => {
    myDataBase.findOne({ _id: new ObjectID(id) }, (err, doc) => {
      if (err) return console.error(err)
      done(null, doc)
    })
  })

  passport.use(
    new LocalStrategy((username, password, done) => {
      myDataBase.findOne({ username: username }, (err, user) => {
        console.log(`User: ${username} attempted to log in.`)
        if (err) return done(err)
        if (!user) return done(null, false)
        if (!bcrypt.compareSync(password, user.password)) return done(null, false)

        return done(null, user)
      })
    })
  )

  passport.use(
    new GitHubStrategy(
      {
        clientID: gitHubClientID,
        clientSecret: gitHubClientSecret,
        callbackURL: githubCallBackUrl,
      },
      function (accessToken, refreshToken, profile, cb) {
        console.log(profile)
        myDataBase.findOneAndUpdate(
          { id: profile.id },
          {
            $setOnInsert: {
              id: profile.id,
              username: profile.username,
              name: profile.displayName || profile.username,
              created_on: new Date(),
              provider: profile.provider || "",
            },
            $set: {
              last_login: new Date(),
            },
            $inc: {
              login_count: 1,
            },
          },
          { upsert: true, new: true },
          (err, doc) => {
            return cb(null, doc?.value)
          }
        )
      }
    )
  )
}
