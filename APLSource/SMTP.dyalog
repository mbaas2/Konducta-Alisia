:Class SMTP

⍝ Based on original work by Conrad Hoesle-Kienzlen in 1999
⍝ Updated by Morten Kromberg to use UTF-8 text, 2009
⍝ Updated by Brian Becker in jan2011 to make compatible with Unix and Unicode
⍝ Updated by Brian Becker in mar2019 to use Conga, make it a class, etc

    (⎕IO ⎕ML)←1

    :field public Server←''   ⍝ server address
    :field public Port←⍬      ⍝ server port (default depends on whether running 587 or 465 (secure))
    :field public From←''     ⍝ default from address for new messages
    :field public Userid←''   ⍝ userid for authentication (defaults to From)
    :field public Domain←''   ⍝ fully qualified domain name for EHLO command
    :field public Org←''      ⍝ optional organization
    :field public ReplyTo←''  ⍝ optional reply to email address
    :field public Password←'' ⍝ optional password (if server requires authentication)
    :field public XMailer←'Dyalog SMTP Client 1.1.0'  ⍝ client identifier
    :field public Secure←¯1   ⍝ indicates whether to use SSL/TLS, 0 = no, 1 = yes, ¯1 = let port number determine
    :field public TLSFlags←32 ⍝ by default, accept server certificate without validating (see Conga User Guide Appendix C)
    :field public CongaRootName←'SMTP'

    :field public shared CongaRef←''   ⍝ user-supplied reference to location of Conga namespace
    :field public shared LDRC←''       ⍝ reference to Conga library instance after CongaRef has been resolved

    :field _clt←''             ⍝ Conga client id
    :field _loggedOn←0
    :field _EHLOResponse←''
    :field _conx←''            ⍝ Conga connection id

    ∇ r←Version
      :Access public shared
      r←'SMTP' '1.4' '2021-09-09'
    ∇

    :property EHLOResponse
    :access public
        ∇ r←get
          r←_EHLOResponse
        ∇
    :endproperty

    :property Clt  ⍝ client
    :access public
        ∇ r←get
          r←_clt
        ∇
    :endproperty

    :property Conx  ⍝ client connection
    :access public
        ∇ r←get
          r←_conx
        ∇
    :endproperty

    :property LoggedOn  ⍝ has authentication taken place?
    :access public
        ∇ r←get
          r←_loggedOn
        ∇
    :endproperty

    :section Utilities
    if←⍴⍨
    unless←↓⍨
    okay←{0=⊃⍺.(rc msg log)←{3↑⍵,(≢⍵)↓¯99 '' ''},⊆⍵}
    empty←0∘∊⍴
    lc←0∘(819⌶)
    splitOn←{⍵{(≢⍺)↓¨⍵⊂⍨⍺⍷⍵}⍵,⍺} ⍝ e.g. response splitOn CRLF

    ∇ r←Config
    ⍝ returns current service configuration
      :Access public
      r←↑{⍵≡'Password':⍵'********' ⋄ ⍵(⍎⍵)}¨⎕THIS⍎'⎕NL ¯2.2 ¯2.3'
    ∇

    ∇ r←CRLF
      r←⎕UCS 13 10
    ∇


    ∇ (rc msg)←Connected;r;state
      :Access public
      msg←'SMTP server has not been connected'
      →0↓⍨rc←Clt≢''
      :Trap 0 ⍝ handle any Conga error, LDRC not defined, etc
          r←LDRC.Describe Clt
      :Else
          →0⊣(rc msg)←0 'Conga could not query client'
      :EndTrap
      :If 0=⊃r ⍝ good Conga return code?
          :Select state←lc 2⊃3↑2⊃r
          :Case 'client'
              (rc msg)←1 'connected'
          :Case 'error'
              (rc msg)←0 'not connected (possible server timeout)'
          :Else
              (rc msg)←0 'unknown client state: ',∊⍕state
          :EndSelect
      :Else
          (rc msg)←0 'non-zero Conga return code'
      :EndIf
    ∇

    :endsection

    ∇ make
      :Access public
      :Implements constructor
    ∇

    ∇ make1 args
      :Access public
      :Implements constructor
     
      ⍝ args is either a vector with up to 6 elements: [1] server, [2] port, [3] userid, [4] password, [5] from, [6] replyto
      ⍝      or a namespace containing named elements
      :Select ⎕NC⊂'args'
      :Case 2.1 ⍝ variable
          (Server Port From Password Userid ReplyTo Secure)←(Server Port From Password Userid ReplyTo Secure){(≢⍺)↑⍵,(≢⍵)↓⍺},⊆args
      :Case 9.1 ⍝ namespace
          (Server Port From Password Userid ReplyTo Secure)←args{6::⍎⍵ ⋄ ⍺⍎⍵}¨'Server' 'Port' 'From' 'Password' 'Userid' 'ReplyTo' 'Secure'
      :Else
          ⎕←'*** invalid constructor argument'
      :EndSelect
    ∇

    ∇ unmake;base
      :Implements destructor
      :Trap 0
          {}Logoff
          :If 0∊≢⎕INSTANCES base←⊃⊃⎕CLASS ⎕THIS
              base.LDRC←''
          :EndIf
      :EndTrap
    ∇

    ∇ r←NewClient args
      :Access public shared
      r←##.⎕NEW ⎕THIS args
    ∇

    ∇ r←NewMessage args
      :Access public
    ⍝ Create a mew message instance
      r←⎕NEW Message args
      r.Client←⎕THIS
      r.(From XMailer ReplyTo Org)←r.(From XMailer ReplyTo Org){0∊⍴⍺:⍵ ⋄ ⍺}¨From XMailer ReplyTo Org
    ∇

    ∇ (rc msg log)←Send mail;logIt;message;text;rec
      :Access public
    ⍝ mail is one of:
    ⍝ ∘ an instance of Message
    ⍝ ∘ a namespace with named elements
    ⍝ ∘ a vector of [1] to, [2] subj, [3] body
     
      log←''
      logIt←{⍵⊣log,←⍵[2]}
      (rc msg log)←¯1 '' ''
     
      ⍝ If one of Userid or From is specified, use it for both
      :If 0∊⍴Userid ⋄ Userid←From ⋄ :EndIf
      :If 0∊⍴From ⋄ From←Userid ⋄ :EndIf

      →Exit if 0<≢msg←(0∊⍴From)/'No From address specified'
      :If 0=mail.⎕NC'From'
      :OrIf 0∊⍴mail.From
          mail.From←From
      :EndIf
     
      :Select ⎕NC⊂'mail'
      :Case 9.2 ⍝ instance
          message←mail
      :CaseList 9.1 2.1 ⍝ namespace or vector
          message←NewMessage mail
      :Else
          →Exit⊣msg←'Invalid argument'
      :EndSelect
     
      →Exit if 0≠⊃logIt(rc msg text)←message.Compose
     
      :If ~⊃Connected
          →Exit if 0≠⊃logIt(rc msg)←Connect     ⍝ connect to SMTP server
      :EndIf
     
      :If ~LoggedOn
          →Exit if 0≠⊃logIt(rc msg)←Logon
      :EndIf
     
      →Exit if 0≠⊃logIt(rc msg)←Ping ⍝ ping the server to make sure it's still up
     
      →Err if 0≠⊃logIt(rc msg)←Do'MAIL FROM: ',message.(normalizeAddr extractAddr From)
      :For rec :In message.(normalizeAddr∘extractAddr¨Recipients)
          {}logIt Do'RCPT TO: ',rec
      :EndFor
      →Err if 0≠⊃logIt(rc msg)←Do'DATA'
      →Err if 0≠⊃logIt(rc msg)←Do text,CRLF,'.'
      →Exit
     Err:
      logIt(rc msg)←Do'RSET'
     Exit:
    ∇

    ∇ (rc msg)←{crlf}Xmit data;tmp
      :Access public
    ⍝ transmit data without waiting for a response
    ⍝ {crlf} is a Boolean (default=0) indicating whether to append CRLF to data
    ⍝ After receiving a "DATA" comment, the SMTP server does not send a response until it receives CRLF,'.',CRLF
    ⍝ so, the typical use of Xmit would be to send the headers and content of the message and ending with a Do CRLF,'.'
      :If 0=⎕NC'crlf' ⋄ crlf←0 ⋄ :EndIf
      msg←'Sent'
      →Exit if 0=rc←⊃tmp←LDRC.Send Clt data,crlf/CRLF
      msg←1↓∊' ',¨⍕¨(tmp,'' '')[2 3]
     Exit:
    ∇

    ∇ (rc msg)←Connect;r;uid;dom;cert
      :Access public
      (rc msg)←¯1 ''
      :If 0∊⍴Server ⋄ →Exit⊣msg←'Server not defined' ⋄ :EndIf
     
      :If 0∊⍴Port ⍝ if port not specified, select default based on Secure
          Port←(1+0⌈Secure)⊃587 465
      :ElseIf ¯1=Secure ⍝ else if Secure is not set, set based on Port
          Secure←Port∊465
      :EndIf
     
      Secure←0⌈Secure
      Port←⊃Port
     
      :If ~Port∊⍳65535 ⋄ →Exit⊣msg←'Invalid Port' ⋄ :EndIf
     
      :If 0∊⍴uid←Userid ⋄ uid←From ⋄ :EndIf
      :If 0∊⍴dom←Domain
          dom←Message.extractAddr uid
          dom←(⌽∧\'@'≠⌽dom)/dom
      :EndIf
     
      :If 0∊⍴dom ⋄ →Exit⊣msg←'Domain not defined' ⋄ :EndIf
     
      :If 0∊⍴LDRC
      :OrIf {0::1 ⋄ 0≠⊃LDRC.Describe'.'}''
          (rc msg)←Init CongaRootName
      :EndIf
     
      cert←⍬
      :If Secure
          :If 0∊⍴LDRC.X509Cert.LDRC ⋄ LDRC.X509Cert.LDRC←LDRC ⋄ :EndIf
          cert←('X509'(⎕NEW LDRC.X509Cert))('SSLValidation'TLSFlags)
      :EndIf
     
     
      :Select ⊃r←LDRC.Clt(''Server Port'text' 2000000,cert)
      :Case 0
          _clt←2⊃r                   ⍝ Conga client name
          :If 0=⊃(rc msg)←Do''       ⍝ retrieve the server response
              (rc msg)←EHLO dom ⍝ log on user domain
              _EHLOResponse←msg
          :Else
              {}LDRC.Close _clt
              _clt←''
          :EndIf
      :Case 100 ⍝ timeout
          msg←'Conga timeout on connect'
      :Else ⍝ some Conga error occured
          _clt←''
          msg←'Conga error: ',,⍕LDRC.Error⊃r
      :EndSelect
     Exit:
    ∇

    ∇ (rc msg)←EHLO domain;resp;m
      :Access public
    ⍝ Some SMTP servers (gmail in particular) break up the response to EHLO into multiple messages
      :If 0=⊃(rc msg)←Do'EHLO ',domain
          resp←msg splitOn CRLF
          :If '250 '≢4↑⊃⊢/resp  ⍝ this makes the assumption that the EHLO response is in 2 parts only
              :If 0=⊃(rc m)←Do''
                  msg,←m
              :Else
                  msg←m
              :EndIf
          :EndIf
      :EndIf
    ∇

    ∇ (rc msg)←Logon;uid;email;rc;dom;elho;auth
      :Access public
    ⍝ Log on to an SMTP mail server optionally using AUTH LOGIN or AUTH PLAIN authentication if userid and password are non-empty
    ⍝  Other authentication types may be added in the future
    ⍝  If no password is set, then authentication is not done
    ⍝
      (rc msg)←0 'No logon performed, Password is not defined'
      →Exit if 0∊⍴Password
      (rc msg)←¯1 ''
      :If ~⊃Connected
          →Exit if 0≠⊃(rc msg)←Connect
      :EndIf
      elho←' '(,⍨)¨(~EHLOResponse∊CRLF)⊆EHLOResponse
      :If 1≠≢auth←('^250.AUTH '⎕S'%')elho
          →Exit⊣msg←'250-AUTH server response was not found or was not proper'
      :EndIf
      uid←(1+0∊⍴Userid)⊃Userid From
      →Exit if~0∊⍴msg←(0∊⍴uid)/'No Userid or From address specified'
      auth←' '(≠⊆⊢)8↓⊃auth
      →('LOGIN' 'PLAIN'∊auth)/LOGIN,PLAIN
      →Exit⊣msg←'Only AUTH LOGIN or AUTH PLAIN are currently supported'
     LOGIN:
      →Exit if 0≠⊃(rc msg)←Do'AUTH LOGIN'
      →Exit if 0≠⊃(rc msg)←Do Message.base64enc uid
      →Exit⊣rc msg←Do Message.base64enc Password
     PLAIN:
      →Exit if 0≠⊃(rc msg)←Do'AUTH PLAIN'
      →Exit⊣rc msg←Do Message.base64enc uid,(⎕UCS 0),uid,(⎕UCS 0),Password
     Exit:
      _loggedOn←0=rc
    ∇

    ∇ (rc msg)←Logoff
      :Access public
    ⍝ Log out from an SMTP mail server
      :If 0=⊃(rc msg)←Do'QUIT'
          rc←⊃LDRC.Close Clt
      :EndIf
      _loggedOn←0
    ∇

    ∇ (rc msg)←Ping
      :Access public
      (rc msg)←Do'NOOP'
    ∇

    ∇ (rc msg)←Reset
      :Access public
      (rc msg)←Do'RSET'
    ∇

    ∇ r←Do cmd;cnt;rc;c
      :Access public
      →go
    ⍝ Send a command to an smtp server and retrieve answer
    ⍝ cmd: smtp command, or mail body, or empty vector
    ⍝      If cmd is an empty vector, the function returns a pending answer
    ⍝      from the server
    ⍝ r    [1]=0 if OK (response was a 2XX) or 1 if error
    ⍝      [2]=status message starting with a 3-digit status number
    ⍝
    ⍝ Valid commands are:
    ⍝ Name Parameter      Description & return codes (S=success, E=error)
    ⍝ ---- -------------  ------------------------------------------------
    ⍝ HELO <domain>       Make yourself known to the server
    ⍝                      S: 250; E: 421 500 501 504
    ⍝ EHLO <domain>       Like HELO but request extended smtp services
    ⍝                      S: 250; E: 421 500 501 504
    ⍝                      NOTE: apart from code 250, the server answers with
    ⍝                            a cr/lf delimited list of supported commands
    ⍝ MAIL FROM:<sender>  Start a new mail, <sender> is your mail address
    ⍝                      S: 250; E: 421 451 452 500 501 552
    ⍝ RCPT TO:<receiver>  Identify the recipients, up to 100 are allowed
    ⍝                      S: 250 251; E: 421 450 451 452 500 501 503 550-553
    ⍝ DATA                Initialize sending mail body
    ⍝                      S: 354; E: 451 452 552 554
    ⍝ <maildata>          Send the mail body (use smtp_stuff to prepare it)
    ⍝                      NOTE: there is no response until "end-of-mail" is sent.
    ⍝ .<cr/lf>            "end-of-mail" command, a line with only a dot and cr/lf
    ⍝                      S: 250; E: 421 451 500 501 503 554
    ⍝ RSET                Cancel the mail just sent
    ⍝                      S: 250; E: 421 500 501 504
    ⍝ VRFY <string>       Verify a recipients mail address (often disabled)
    ⍝                      S: 250 251; E: 421 500 501 502 504 550 551 553
    ⍝ EXPN <string>       Expand a mailing list (often disabled)
    ⍝                      S: 250; E: 421 500 501 502 504 550
    ⍝ HELP [<string>]     Return a help message, optionally followed by a command
    ⍝                      S: 211 214; E: 421 500 501 502 504
    ⍝ NOOP                Returns success or error
    ⍝                      S: 250; E: 421 500
    ⍝ QUIT                End the smtp session
    ⍝                      S: 221; E: 500
    ⍝ TURN                Reverse the roles of client and server (DON't USE!)
    ⍝                      S: 250; E: 500 502 503
    ⍝
    ⍝ Meaning of the return codes:
    ⍝ NOTE: If the 3-digit number is followed by "-", there is more data to follow
    ⍝ 211 System status, or system help reply
    ⍝ 214 Help message
    ⍝ 220 <domain> Service ready
    ⍝ 221 <domain> Service closing transmission channel
    ⍝ 250 Requested mail action okay, completed
    ⍝ 251 User not local; will forward to <forward-path> (this is not an error!)
    ⍝ 354 Start mail input; end with <CRLF>.<CRLF>
    ⍝ 421 <domain> Service not available, closing transmission channel
    ⍝ 450 Requested mail action not taken: mailbox unavailable [E.g., mailbox busy]
    ⍝ 451 Requested action aborted: local error in processing
    ⍝ 452 Requested action not taken: insufficient system storage
    ⍝ 500 Syntax error, command unrecognized
    ⍝ 501 Syntax error in parameters or arguments
    ⍝ 502 Command not implemented
    ⍝ 503 Bad sequence of commands
    ⍝ 504 Command parameter not implemented
    ⍝ 550 Requested action not taken: mailbox unavailable
    ⍝ 551 User not local; please try <forward-path>
    ⍝ 552 Requested mail action aborted: exceeded storage allocation
    ⍝ 553 Requested action not taken: mailbox name not allowed (typo?)
    ⍝ 555 Only used by this program to indicate a special error condition
     go:
      :If ⊃c←Connected                   ⍝ if we're connected
          :If ~empty cmd
              :If 0≠⊃rc←LDRC.Send Clt(cmd,CRLF)
                  →Exit⊣r←'555 Conga error: ',,⍕2↑rc
              :EndIf
          :EndIf
          cnt←0
     Try:
          :Select ⊃rc←LDRC.Wait Clt 2000  ⍝ wait up to 2 seconds
          :Case 0
              r←¯2↓4⊃rc                     ⍝ grab the data
          :Case 100                         ⍝ timeout, try up to 3 times
              cnt+←1
              →Try if 3>cnt
              r←'555 Conga timeout'
          :Else
              r←'555 Conga error: ',,⍕2↑rc
          :EndSelect
      :Else                              ⍝ if the socket does not exist
          r←'555 SMTP server not connected - ',2⊃c
      :EndIf
     Exit:
      r←((⊃r)∊'45')r                    ⍝ check for error and return
    ∇

    :Class Message
        :Field public From←''
        :Field public Subj←''
        :Field public ReplyTo←''
        :Field public Org←''
        :Field public To←''           ⍝ vector of email addresses
        :Field public CC←''           ⍝ vector of email addresses
        :Field public BCC←''          ⍝ vector of email addresses
        :Field public Headers←''      ⍝ vector of ('name' 'value')
        :Field public XMailer←''
        :Field public Body←''         ⍝ character vector 'content' or vector of ('MIMEType' 'content')
        :Field public Attachments←''  ⍝ vector of ('filename' 'MIMEType' {'content'|''})
        :Field public Client          ⍝ reference to SMTP client that created this
:field public BodyIsRawMessage←0  ⍝ MB

        :Field _text←''
        :field _recipients←''

        :property Text
        :access public
            ∇ r←Get
              r←_text
            ∇
        :endproperty

        :property Recipients
        :access public
            ∇ r←Get
              r←_recipients
            ∇
        :endproperty

        default←{0∊⍴⍺ : ⍵ ⋄ ⍺}

        ∇ make
          :Access public
          :Implements constructor
        ∇

        ∇ make1 args
          :Access public
          :Implements constructor
          :Select ⎕NC⊂'args' ⍝ namespace?
          :Case 9.1
              args{
                  0≠⍺.⎕NC ⍵:⍎⍵,'←⍺⍎⍵'
              }¨'From' 'Subj' 'ReplyTo' 'Org' 'To' 'CC' 'BCC' 'MIMEType' 'Headers' 'Body' 'Attachments' 'BodyIsRawMessage'
          :Case 2.1 ⍝ 'To' 'Subj' 'Body' {'MIMEType'}
              args←,⊆args
              (To Subj Body MIMEType)←4↑args,(≢args)↓'' '' '' ''
          :Else
              'Invalid constructor argument'⎕SIGNAL 11
          :EndSelect
        ∇

        ∇ (rc msg text)←Compose;addHeader;haveAtts;boundary;mime;body;atts;i;n;att
          :Access public
        ⍝ Compose email content
          (rc msg text)←¯1 '' ''
          :if 2=⎕nc'BodyIsRawMessage'
          :andif BodyIsRawMessage
              text←Body
              MakeRecipients
              rc←0
              →0
              :endif
          :If 0∊⍴From ⋄ →Exit⊣msg←'"From" is not defined' ⋄ :EndIf
          :If 0∊⍴Subj ⋄ →Exit⊣msg←'"Subj" is not defined' ⋄ :EndIf
          :If (0∊⍴Body)∧0∊⍴Attachments ⋄ →Exit⊣msg←'No body or attachments are defined' ⋄ :EndIf
          MakeRecipients
          :If 0∊⍴Recipients ⋄ →Exit⊣msg←'No recipients are defined' ⋄ :EndIf
         
          addHeader←{
              ⍵∧.=' ':''
              128∧.>⎕UCS ⍵:⍺,': ',⍵,⎕UCS 13 10
              ⍺,': =?utf-8?B?',(base64enc ⍵),'?=',⎕UCS 13 10
          }
         
          text←'Date'addHeader now    ⍝ Internet-conform date first
          text,←'From'addHeader normalizeAddr From  ⍝ the user's name & mail address
          text,←'Reply-To'addHeader normalizeAddr ReplyTo ⍝ the reply-to address
          text,←'Organization'addHeader Org
          text,←'X-Mailer'addHeader XMailer
          text,←'MIME-Version'addHeader'1.0'
          text,←∊CRLF∘(,⍨)¨('B'≠⊃¨Recipients)/Recipients ⍝ no headers for BCC recipients
          text,←'Subject'addHeader Subj ⍝ the message subject
         
          :If haveAtts←~0∊⍴Attachments ⍝ Any attachments?
              boundary←'------',(∊⍕¨⎕TS),'.DyalogSMTP',CRLF ⍝ construct a boundary for attachments
              text,←'Content-Type'addHeader'multipart/mixed; boundary="',(¯2↓boundary),'"'
              text,←CRLF
              text,←'This is a multi-part message in MIME format.',CRLF
              text,←'--',boundary
          :EndIf
         
          :If ~0∊⍴Body
              (mime body)←¯2↑'' '',⊆Body
              :If Body beginsWith'file://'
                  body←⊃⎕NGET 7↓Body
              :EndIf
              :If 0∊⍴mime
                  mime←(1+'<html'≡0(819⌶)5↑body)⊃'plain' 'html'
                  mime←'text/',mime,'; charset=utf-8;'
              :EndIf
              text,←'Content-Type'addHeader mime
              text,←'Content-Transfer-Encoding'addHeader'8bit'
              text,←CRLF
              text,←⎕UCS'UTF-8'⎕UCS{2↓{∊(⊂'..')@(⎕←⍸(⍵='.')∧¯1↓1,⍵∊CRLF)⊢⍵}CRLF,⍵}body   ⍝ stuff leading dots
              text,←CRLF
          :EndIf
         
          :If haveAtts
              text,←haveAtts/boundary
         
              Attachments←FormatAttachments Attachments
         
              :For i :In ⍳n←≢Attachments
                  :If 0∊⍴att←i Attachment i⊃Attachments
                      msg←'Error processing attachment ',(⍕i),', file="',(1⊃i⊃Attachments),'"'
                      →Exit
                  :EndIf
                  text,←att
                  text,←boundary
                  :If i=n ⍝ last attachment?
                      text←(¯2↓text),'--',CRLF
                  :EndIf
              :EndFor
          :EndIf
          (rc msg)←0 ''
         Exit:
        ∇

        ∇ Attach attachment
          :Access public
          Attachments←(FormatAttachments⍣(~0∊⍴Attachments)⊢Attachments),FormatAttachments attachment
        ∇

        ∇ atts←FormatAttachments atts
          :Access public shared
          :Select |≡atts
          :CaseList 0 1  ⍝ 'filename'
              atts←,⊂(⊂,atts),'' ''
          :Case 2   ⍝ 'filename' 'mimetype' {'content'}
              atts←,⊂atts
          :Case 3   ⍝ ('filename' 'mimetype')('filename' '
          :EndSelect
        ∇

        ∇ r←Send
          :Access public
          r←Client.Send ⎕THIS
        ∇

        ∇ r←i Attachment arg;mime;content;file;name
          (file mime content)←3↑(⊆arg),'' '' ''
          :If 0∊⍴file
              name←'Attachment-',(⍕i),,'<->,4ZI2,<.>,ZI3'⎕FMT 1 5⍴2↓⎕TS  ⍝ make an arbitrary one
          :Else
              name←∊¯2↑⎕NPARTS file←(7×'file://'≡7↑file)↓file
              :If 0∊⍴content ⍝ attempt to read content
                  content←ReadFile file
              :EndIf
          :EndIf
          r←''
          :If ~0∊⍴content
              :If 0∊⍴mime ⋄ mime←'application/octet-stream' ⋄ :EndIf
              r←'Content-Type: ',mime,'; name="',name,'"',CRLF
              r,←'Content-Transfer-Encoding: base64',CRLF
              r,←'Content-Disposition: attachment; filename="',name,'"',CRLF,CRLF
              r,←chunk base64enc content
          :EndIf
        ∇

        ∇ r←ReadFile file
          r←{0::'' ⋄ {(⎕NUNTIE ⍵)⊢⎕NREAD ⍵,(⎕DR' '),¯1 0},⍵ ⎕NTIE 0}file
        ∇

        ∇ MakeRecipients;addrs
          :Access public
          _recipients←''
          _recipients,←'To'FormatList To
          _recipients,←'CC'FormatList CC
          _recipients,←'BCC'FormatList BCC
        ∇

        ∇ list←type FormatList list
          :Access public shared
        ⍝ list may be a matrix, a simple (delimited) vector, or a vector of vectors
          :If ~0∊⍴list
              :If 2=≢⍴list ⍝ matrix of names?
                  list←↓list
              :ElseIf (≡list)∊0 1
                  list←list((~∊)⊆⊣)',;' ⍝ otherwise split on ; or ,
              :EndIf
              list←{⍵↓⍨-+/∧\' '=⌽⍵}¨list
              list←(type,': ')∘,¨normalizeAddr¨list
          :EndIf
        ∇

        ∇ r←CRLF
          :Access public shared
          r←⎕UCS 13 10
        ∇

        ∇ r←{len}chunk content;breaks;mask;stuff
          :Access public shared
        ⍝ Convert content into a vector with embedded cr/lf plus dot-stuffing
        ⍝ len : the maximum line length, excluding cr/lf line ends. Defaults to 72,
        ⍝       as 74 is a safe line length to transmit through SMTP
        ⍝ rc  : A string with cr/lf every len characters and dot-stuffing
        ⍝ NOTE: It is safe to send a Base64-encoded string through this function,
        ⍝       as those strings do not contain any dots. However, the function does
        ⍝       not work well if there are cr/lf already present in the input.
        ⍝ Dot-Stuffing: The end of an SMTP mail text is indicated by transmitting
        ⍝               a line with a single dot. This means, that the original
        ⍝               mail text must not contain a single dot on a line by itself.
        ⍝               To prevent this, every line that starts with a dot get's
        ⍝               preceeded with a second dot, which will be removed by the
        ⍝               recipients mail client. See pop3_unstuff, the reverse function.
         
          stuff←{'.'=⊃⍵:'.',⍵ ⋄ ⍵}
         
          :If 900⌶⍬ ⋄ len←72 ⋄ :EndIf    ⍝ default line length, if not given
          :If 2>|≡content ⍝ simple array? otherwise, treat it as a vector of vectors
              :Select ≢⍴content
              :Case 0
                  content←,⊂,content
              :Case 1
                  :If ∨/CRLF∊content         ⍝ any line breaks?
                      content,⍨←CRLF
                      breaks←CRLF∘.=content
                      content←(~∘⊂CRLF)¨content⊂⍨(∨⌿breaks)≠breaks[2;]∧¯1↓0,breaks[1;] ⍝ break on CRLF or lone CR or lone LF
                  :Else
                      content←,⊂content
                  :EndIf
              :Case 2
                  content←↓content
              :Else
                  content←↓((×/¯1↓⍴content),¯1↑⍴content)⍴content
              :EndSelect
          :EndIf
         
          content←{⍵↓⍨-⊥⍨' '=⍵}¨content ⍝ delete trailing blanks
          content←stuff¨content ⍝ dot-stuff (double leading dot)
         
          :If ∨/mask←len<≢¨content  ⍝ any lines longer than length?
              :If 1=≢content ⍝ single chunk
                  content←{((≢⍵)⍴len↑1)⊂⍵}⊃content
                  (1↓content)←stuff¨1↓content
              :Else
                  content←({⊂len∘chunk ⍵}@{mask})content
              :EndIf
          :EndIf
          r←∊content,¨⊂CRLF
        ∇

        ∇ r←extractAddr addr;quotes;ind;del
          :Access public shared
        ⍝ extract the mail address from a string
        ⍝ perform very cursory validation on the address
        ⍝ addr - the string to be validated (can be in form "Fred Bloggs" fred@bloggs.com)
        ⍝ r    - the email address or empty if not valid
          r←''
          quotes←(⊢∨≠\)'"'=addr ⍝ mask out quoted material e.g. "fred@work" fred@bloggs.com
          ind←⊃⍸quotes<addr='@'
          :If ind≠0
              del←0,(1+≢addr),⍨⍸quotes<' '=addr ⍝ break on space
              r←addr{⍵[1]↓(¯1+⍵[2])↑⍺}del[0 1+del⍸ind]
              r←⊃('.+@[^.].+\..+'⎕S'%')r
          :EndIf
        ∇

        ∇ addr←normalizeAddr addr;a
          :Access public shared
          :If 0<≢addr~' '  ⍝ MB: avoid issues when addr is a 0/ManyAddrs
              :If '<>'≢(⊣/,⊢/)a←extractAddr addr
                  addr←(addr/⍨~∨\⌽<\⌽a⍷addr),'<',a,'>'
              :EndIf
          :EndIf
        ∇

        ∇ r←base64 w
        ⍝ from dfns workspace
          :Access public shared
          r←{⎕IO ⎕ML←0 1             ⍝ Base64 encoding and decoding as used in MIME.
              chars←'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
              bits←{,⍉(⍺⍴2)⊤⍵}                   ⍝ encode each element of ⍵ in ⍺ bits,
                                                 ⍝   and catenate them all together
              part←{((⍴⍵)⍴⍺↑1)⊂⍵}                ⍝ partition ⍵ into chunks of length ⍺
              0=2|⎕DR ⍵:2∘⊥∘(8∘↑)¨8 part{(-8|⍴⍵)↓⍵}6 bits{(⍵≠64)/⍵}chars⍳⍵
                                       ⍝ decode a string into octets
              four←{                             ⍝ use 4 characters to encode either
                  8=⍴⍵:'=='∇ ⍵,0 0 0 0           ⍝   1,
                  16=⍴⍵:'='∇ ⍵,0 0               ⍝   2
                  chars[2∘⊥¨6 part ⍵],⍺          ⍝   or 3 octets of input
              }
              cats←⊃∘(,/)∘((⊂'')∘,)              ⍝ catenate zero or more strings
              cats''∘four¨24 part 8 bits ⍵
          }w
        ∇

        ∇ b64←base64enc txt
          :Access public shared
          b64←base64'UTF-8'⎕UCS txt
        ∇

        ∇ txt←base64dec b64
          :Access public shared
          txt←'UTF-8'⎕UCS base64 b64
        ∇

        ∇ rc←now;time;day;mon;s;x;LOCTIME;TIMEZONE;isUnicode;twid
          :Access public shared
        ⍝ returns an internet-conforming (RFC 5322) timestamp
          :If 'Win'≡3↑⊃'.'⎕WG'APLVersion'
              isUnicode←80=⎕DR'A'
              twid←64 32[1+isUnicode] ⍝ set width for text elements based on unicode or not
              'LOCTIME'⎕NA'KERNEL32.C32|GetLocalTime >{I2[8]}' ⍝ associate GetLocalTime function
              'TIMEZONE'⎕NA'U4 KERNEL32.C32|GetTimeZoneInformation >{I4 T[',(⍕twid),'] {I2[8]} I4 T[',(⍕twid),'] {I2[8]} I4}' ⍝ associate GetTimeZone function
        ⍝ prepare values for time formatting
              day←'Sun,' 'Mon,' 'Tue,' 'Wed,' 'Thu,' 'Fri,' 'Sat,'
              mon←'Jan ' 'Feb ' 'Mar ' 'Apr ' 'May ' 'Jun ' 'Jul ' 'Aug ' 'Sep ' 'Oct ' 'Nov ' 'Dec '
        ⍝ read the local time and format to Internet standard
              time←⊃LOCTIME⊂8⍴1000
              rc←(1+time[3])⊃day
              rc←rc,,'< >,ZI2,< >'⎕FMT time[4]
              rc←rc,time[2]⊃mon
              rc←rc,,'I4,< >,ZI2,<:>,ZI2,<:>,ZI2,< >'⎕FMT 1 4⍴time[1 5 6 7]
        ⍝ call timezone function and calculate offset from GMT
              x←TIMEZONE⊂0(twid⍴' ')(8⍴0)0(twid⍴' ')(8⍴0)0
              x←(1⌈⊃x),2⊃x ⍝ 1⌈ to accomodate timezones that do not recognize daylight savings time
              s←'+-'[1+0>x←(-2⊃x)+-x[(5 8)[⊃x]]]
              rc←rc,s,,'ZI4,< (UTC)>'⎕FMT|100×x÷60
          :Else
              rc←1⊃⎕SH'date -R' ⍝ unix - call date command
          :EndIf
        ∇

        ∇ r←Config
        ⍝ returns current message configuration
          :Access public
          r←↑{⍵(⍎⍵)}¨⎕THIS⍎'⎕NL ¯2.2 ¯2.3'
        ∇

        beginsWith←{⍵≡(≢⍵)↑⍺}
    :EndClass

    :section Conga
    ∇ (rc msg)←Init rootname;ref;root;nc;class;dyalog;n;ns;congaCopied
      (rc msg)←¯1 ''
      ⍝↓↓↓ Check is LDRC exists (VALUE ERROR (6) if not), and is LDRC initialized? (NONCE ERROR (16) if not)
      :Hold 'SMTPInit'
          :If {6 16 999::1 ⋄ ''≡LDRC:1 ⋄ 0⊣LDRC.Describe'.'}''
              LDRC←''
              :If 9=#.⎕NC'Conga' ⋄ {#.Conga.X509Cert.LDRC←''}⍬ ⋄ :EndIf ⍝ if #.Conga exists, reset X509Cert.LDRC reference
              :If ~0∊⍴CongaRef  ⍝ did the user supply a reference to Conga?
                  LDRC←rootname ResolveCongaRef CongaRef
                  :If ''≡LDRC
                      msg←'CongaRef (',(⍕CongaRef),') does not point to a valid instance of Conga'
                      →Exit
                  :EndIf
              :Else
                  :For root :In ##.## #
                      ref nc←root{1↑¨⍵{(×⍵)∘/¨⍺ ⍵}⍺.⎕NC ⍵}ns←(-~0∊⍴rootname)↓'Conga' 'DRC' ⍝ if rootname is supplied, can only use Conga (no DRC)
                      :If 9=⊃⌊nc ⋄ :Leave ⋄ :EndIf
                  :EndFor
                  :If 9=⊃⌊nc
                      LDRC←rootname ResolveCongaRef root⍎∊ref
                      :If ''≡LDRC
                          msg←(⍕root),'.',(∊ref),' does not point to a valid instance of Conga'
                          →Exit
                      :EndIf
                      →∆COPY↓⍨{999::0 ⋄ 1⊣LDRC.Describe'.'}'' ⍝ it's possible that Conga was saved in a semi-initialized state
                  :Else
     ∆COPY:
                      class←⊃⊃⎕CLASS ⎕THIS
                      dyalog←{⍵,'/'↓⍨'/\'∊⍨¯1↑⍵}2 ⎕NQ'.' 'GetEnvironment' 'DYALOG'
                      congaCopied←0
                      :For n :In ns
                          :Trap 0
                              n class.⎕CY dyalog,'ws/conga'
                              LDRC←rootname ResolveCongaRef class⍎n
                              :If ''≡LDRC
                                  msg←n,' was copied from [DYALOG]/ws/conga, but is not valid'
                                  →Exit
                              :EndIf
                              congaCopied←1
                              :Leave
                          :EndTrap
                      :EndFor
                      :If ~congaCopied
                          msg←'Neither Conga nor DRC were successfully copied from [DYALOG]/ws/conga'
                          →Exit
                      :EndIf
                  :EndIf
              :EndIf
          :EndIf
          rc←¯1×LDRC≢''
     Exit:
      :EndHold
    ∇

    ∇ LDRC←rootname ResolveCongaRef CongaRef;z;failed
    ⍝ CongaRef could be a charvec, reference to the Conga or DRC namespaces, or reference to an iConga instance
    ⍝ :Access public shared  ⍝!!! testing only  - remove :Access after testing
      LDRC←'' ⋄ failed←0
      :Select ⎕NC⊂'CongaRef' ⍝ what is it?
      :Case 9.1 ⍝ namespace?  e.g. CongaRef←DRC or Conga
     Try:
          :Trap 0
              :If ∨/'.Conga'⍷⍕CongaRef ⍝ is it Conga?
                  LDRC←CongaRef.Init rootname
              :ElseIf 0≡⊃CongaRef.Init'' ⍝ DRC?
                  LDRC←CongaRef
              :Else
                  →0⊣LDRC←''
              :End
          :Else ⍝ if HttpCommand is reloaded and re-executed in rapid succession, Conga initialization may fail, so we try twice
              :If failed
                  →0⊣LDRC←''
              :Else
                  →Try⊣failed←1
              :EndIf
          :EndTrap
      :Case 9.2 ⍝ instance?  e.g. CongaRef←Conga.Init ''
          LDRC←CongaRef ⍝ an instance is already initialized
      :Case 2.1 ⍝ variable?  e.g. CongaRef←'#.Conga'
          :Trap 0
              LDRC←ResolveCongaRef(⍎∊⍕CongaRef)
          :EndTrap
      :EndSelect
    ∇
    :endsection

:EndClass
