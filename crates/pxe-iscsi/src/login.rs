use std::{io, net::SocketAddr};

use crate::pdu::{LoginRequest, LoginResponse, Stage, TextRequest, TextResponse};

const DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH: u32 = 262_144;
const DEFAULT_MAX_BURST_LENGTH: u32 = 262_144;
const DEFAULT_FIRST_BURST_LENGTH: u32 = DEFAULT_MAX_BURST_LENGTH;
const DEFAULT_TSIH: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    Discovery,
    Normal { tsih: u16, cmd_sn_start: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionType {
    Discovery,
    Normal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginState {
    SecurityNegotiation,
    LoginOperational(SessionType),
    FullFeature(SessionType),
}

pub struct LoginSession {
    target_iqn: String,
    target_addr: SocketAddr,
    state: LoginState,
    stat_sn: u32,
    tsih: u16,
}

impl LoginSession {
    pub fn new(target_iqn: impl Into<String>, target_addr: SocketAddr) -> Self {
        Self {
            target_iqn: target_iqn.into(),
            target_addr,
            state: LoginState::SecurityNegotiation,
            stat_sn: 1,
            tsih: DEFAULT_TSIH,
        }
    }

    pub fn handle_login_request(
        &mut self,
        req: &LoginRequest,
    ) -> io::Result<(LoginResponse, Option<SessionOutcome>)> {
        validate_login_version(req)?;

        let params = parse_text_parameters(&req.data)?;
        let requested_session_type = parse_session_type(find_param(&params, "SessionType"))?;
        let session_type = match self.state {
            LoginState::SecurityNegotiation => requested_session_type,
            LoginState::LoginOperational(existing) => existing,
            LoginState::FullFeature(existing) => existing,
        };
        log::debug!(
            "iscsi: login state={:?} requested_session={:?}",
            self.state,
            session_type
        );

        match self.state {
            LoginState::SecurityNegotiation => {
                if req.csg != Stage::SecurityNegotiation as u8
                    || req.nsg != Stage::LoginOperational as u8
                {
                    return Err(invalid_login_stage());
                }

                let data = build_login_response_data(&params, session_type, &self.target_iqn)?;
                let exp_cmd_sn = req.cmd_sn.wrapping_add(1);
                self.state = LoginState::LoginOperational(session_type);
                log::debug!(
                    "iscsi: login transition -> {:?} exp_cmd_sn={} stat_sn={}",
                    self.state,
                    exp_cmd_sn,
                    self.stat_sn
                );

                Ok((
                    make_login_response(
                        req,
                        LoginResponseBuild {
                            transit: true,
                            csg: Stage::SecurityNegotiation,
                            nsg: Stage::LoginOperational,
                            tsih: self.tsih,
                            data,
                            exp_cmd_sn,
                            max_cmd_sn: exp_cmd_sn,
                            stat_sn: self.next_stat_sn(),
                        },
                    ),
                    None,
                ))
            }
            LoginState::LoginOperational(existing) => {
                if existing != session_type {
                    return Err(invalid_login_stage());
                }
                if !req.transit
                    || req.csg != Stage::LoginOperational as u8
                    || req.nsg != Stage::FullFeature as u8
                {
                    return Err(invalid_login_stage());
                }

                let data = build_login_response_data(&params, session_type, &self.target_iqn)?;
                let exp_cmd_sn = req.cmd_sn.wrapping_add(1);
                self.state = LoginState::FullFeature(session_type);
                log::debug!(
                    "iscsi: login transition -> {:?} exp_cmd_sn={} stat_sn={}",
                    self.state,
                    exp_cmd_sn,
                    self.stat_sn
                );

                let outcome = match session_type {
                    SessionType::Discovery => SessionOutcome::Discovery,
                    SessionType::Normal => SessionOutcome::Normal {
                        tsih: self.tsih,
                        cmd_sn_start: exp_cmd_sn,
                    },
                };

                Ok((
                    make_login_response(
                        req,
                        LoginResponseBuild {
                            transit: true,
                            csg: Stage::LoginOperational,
                            nsg: Stage::FullFeature,
                            tsih: self.tsih,
                            data,
                            exp_cmd_sn,
                            max_cmd_sn: exp_cmd_sn,
                            stat_sn: self.next_stat_sn(),
                        },
                    ),
                    Some(outcome),
                ))
            }
            LoginState::FullFeature(_) => Err(invalid_login_stage()),
        }
    }

    pub fn handle_text_request(&mut self, req: &TextRequest) -> io::Result<TextResponse> {
        let session_type = match self.state {
            LoginState::FullFeature(session_type) => session_type,
            _ => return Err(invalid_login_stage()),
        };

        let params = parse_text_parameters(&req.data)?;
        let send_targets_all = find_param(&params, "SendTargets")
            .is_some_and(|value| value.eq_ignore_ascii_case("All"));

        let mut data = Vec::new();
        if session_type == SessionType::Discovery && send_targets_all {
            push_text_pair(&mut data, "TargetName", &self.target_iqn);
            push_text_pair(
                &mut data,
                "TargetAddress",
                &format!("{},1", self.target_addr),
            );
        } else {
            push_text_pair(&mut data, "SendTargets", "NotUnderstood");
        }

        let exp_cmd_sn = req.cmd_sn.wrapping_add(1); // RFC 3720 §3.3.1: modular
        Ok(TextResponse {
            final_: true,
            initiator_task_tag: req.initiator_task_tag,
            target_transfer_tag: 0xFFFF_FFFF,
            stat_sn: self.next_stat_sn(),
            exp_cmd_sn,
            max_cmd_sn: exp_cmd_sn,
            data,
        })
    }

    pub fn stat_sn(&self) -> u32 {
        self.stat_sn
    }

    fn next_stat_sn(&mut self) -> u32 {
        let stat_sn = self.stat_sn;
        self.stat_sn = self.stat_sn.wrapping_add(1); // RFC 3720 §3.3.1: 32-bit modular counter
        stat_sn
    }
}

pub fn describe_text_parameters(data: &[u8]) -> String {
    match parse_text_parameters(data) {
        Ok(params) if params.is_empty() => "<none>".to_string(),
        Ok(params) => params
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", "),
        Err(err) => format!("<invalid text params: {err}>"),
    }
}

fn validate_login_version(req: &LoginRequest) -> io::Result<()> {
    if req.version_max != 0 || req.version_min != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported iSCSI version",
        ));
    }
    Ok(())
}

fn invalid_login_stage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid iSCSI login stage transition",
    )
}

fn parse_session_type(value: Option<&str>) -> io::Result<SessionType> {
    match value {
        Some(v) if v.eq_ignore_ascii_case("Discovery") => Ok(SessionType::Discovery),
        Some(v) if v.eq_ignore_ascii_case("Normal") => Ok(SessionType::Normal),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SessionType value",
        )),
        None => Ok(SessionType::Normal),
    }
}

fn parse_text_parameters(data: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut params = Vec::new();

    for field in data.split(|b| *b == 0) {
        if field.is_empty() {
            continue;
        }

        let text = std::str::from_utf8(field).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "login text is not valid UTF-8")
        })?;
        let (key, value) = text.split_once('=').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "login text key is missing '='")
        })?;
        params.push((key.to_string(), value.to_string()));
    }

    Ok(params)
}

fn find_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn build_login_response_data(
    params: &[(String, String)],
    session_type: SessionType,
    target_iqn: &str,
) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();

    push_text_pair(
        &mut data,
        "SessionType",
        match session_type {
            SessionType::Discovery => "Discovery",
            SessionType::Normal => "Normal",
        },
    );
    push_text_pair(
        &mut data,
        "MaxRecvDataSegmentLength",
        &DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH.to_string(),
    );
    push_text_pair(&mut data, "HeaderDigest", "None");
    push_text_pair(&mut data, "DataDigest", "None");
    push_text_pair(&mut data, "InitialR2T", "No");
    push_text_pair(&mut data, "ImmediateData", "Yes");
    push_text_pair(
        &mut data,
        "MaxBurstLength",
        &DEFAULT_MAX_BURST_LENGTH.to_string(),
    );
    push_text_pair(
        &mut data,
        "FirstBurstLength",
        &DEFAULT_FIRST_BURST_LENGTH.to_string(),
    );

    if session_type == SessionType::Discovery {
        push_text_pair(&mut data, "TargetName", target_iqn);
    }

    for (key, _) in params {
        if is_login_key_recognized(key) {
            continue;
        }
        push_text_pair(&mut data, key, "NotUnderstood");
    }

    Ok(data)
}

fn is_login_key_recognized(key: &str) -> bool {
    key.eq_ignore_ascii_case("InitiatorName")
        || key.eq_ignore_ascii_case("SessionType")
        || key.eq_ignore_ascii_case("MaxRecvDataSegmentLength")
        || key.eq_ignore_ascii_case("MaxBurstLength")
        || key.eq_ignore_ascii_case("FirstBurstLength")
        || key.eq_ignore_ascii_case("InitialR2T")
        || key.eq_ignore_ascii_case("ImmediateData")
        || key.eq_ignore_ascii_case("HeaderDigest")
        || key.eq_ignore_ascii_case("DataDigest")
        || key.eq_ignore_ascii_case("AuthMethod")
}

fn push_text_pair(buf: &mut Vec<u8>, key: &str, value: &str) {
    buf.extend_from_slice(key.as_bytes());
    buf.push(b'=');
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
}

struct LoginResponseBuild {
    transit: bool,
    csg: Stage,
    nsg: Stage,
    tsih: u16,
    data: Vec<u8>,
    exp_cmd_sn: u32,
    max_cmd_sn: u32,
    stat_sn: u32,
}

fn make_login_response(req: &LoginRequest, build: LoginResponseBuild) -> LoginResponse {
    LoginResponse {
        transit: build.transit,
        continue_: false,
        csg: build.csg as u8,
        nsg: build.nsg as u8,
        version_max: 0,
        version_active: 0,
        isid: req.isid,
        tsih: build.tsih,
        initiator_task_tag: req.initiator_task_tag,
        status_class: 0,
        status_detail: 0,
        stat_sn: build.stat_sn,
        exp_cmd_sn: build.exp_cmd_sn,
        max_cmd_sn: build.max_cmd_sn,
        data: build.data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_request(data: &[u8]) -> LoginRequest {
        LoginRequest {
            transit: false,
            continue_: false,
            csg: Stage::SecurityNegotiation as u8,
            nsg: Stage::LoginOperational as u8,
            version_max: 0,
            version_min: 0,
            isid: [0x40, 1, 2, 3, 4, 5],
            tsih: 0,
            initiator_task_tag: 0x1122_3344,
            cid: 7,
            cmd_sn: 100,
            exp_stat_sn: 1,
            data: data.to_vec(),
        }
    }

    #[test]
    fn normal_login_negotiates_full_feature() {
        let addr = "192.0.2.1:3260".parse().unwrap();
        let mut session = LoginSession::new("iqn.2024-01.io.pxeasy:boot", addr);

        let req = login_request(b"InitiatorName=iqn.client\0SessionType=Normal\0");
        let (resp1, outcome1) = session.handle_login_request(&req).unwrap();
        assert!(resp1.transit);
        assert_eq!(resp1.csg, Stage::SecurityNegotiation as u8);
        assert_eq!(resp1.nsg, Stage::LoginOperational as u8);
        assert!(outcome1.is_none());
        assert!(resp1
            .data
            .windows(b"SessionType=Normal\0".len())
            .any(|w| w == b"SessionType=Normal\0"));

        let mut req2 = login_request(b"InitiatorName=iqn.client\0SessionType=Normal\0");
        req2.transit = true;
        req2.csg = Stage::LoginOperational as u8;
        req2.nsg = Stage::FullFeature as u8;
        req2.cmd_sn = 101;

        let (resp2, outcome2) = session.handle_login_request(&req2).unwrap();
        assert!(resp2.transit);
        assert_eq!(resp2.csg, Stage::LoginOperational as u8);
        assert_eq!(resp2.nsg, Stage::FullFeature as u8);
        assert_eq!(
            outcome2,
            Some(SessionOutcome::Normal {
                tsih: 1,
                cmd_sn_start: 102
            })
        );
    }

    #[test]
    fn discovery_login_and_send_targets() {
        let addr = "192.0.2.1:3260".parse().unwrap();
        let mut session = LoginSession::new("iqn.2024-01.io.pxeasy:boot", addr);

        let req = login_request(b"InitiatorName=iqn.client\0SessionType=Discovery\0");
        let (_resp1, _outcome1) = session.handle_login_request(&req).unwrap();

        let mut req2 = login_request(b"InitiatorName=iqn.client\0SessionType=Discovery\0");
        req2.transit = true;
        req2.csg = Stage::LoginOperational as u8;
        req2.nsg = Stage::FullFeature as u8;
        req2.cmd_sn = 101;

        let (_resp2, outcome2) = session.handle_login_request(&req2).unwrap();
        assert_eq!(outcome2, Some(SessionOutcome::Discovery));

        let text_req = TextRequest {
            final_: true,
            initiator_task_tag: 0x5566_7788,
            target_transfer_tag: 0xFFFF_FFFF,
            cmd_sn: 200,
            data: b"SendTargets=All\0".to_vec(),
        };

        let text_resp = session.handle_text_request(&text_req).unwrap();
        assert!(text_resp.final_);
        assert_eq!(text_resp.target_transfer_tag, 0xFFFF_FFFF);
        assert!(text_resp
            .data
            .windows(b"TargetName=iqn.2024-01.io.pxeasy:boot\0".len())
            .any(|w| w == b"TargetName=iqn.2024-01.io.pxeasy:boot\0"));
        assert!(text_resp
            .data
            .windows(b"TargetAddress=192.0.2.1:3260,1\0".len())
            .any(|w| w == b"TargetAddress=192.0.2.1:3260,1\0"));
    }

    #[test]
    fn missing_initiator_name_is_accepted() {
        let addr = "192.0.2.1:3260".parse().unwrap();
        let mut session = LoginSession::new("iqn.2024-01.io.pxeasy:boot", addr);
        let req = login_request(b"SessionType=Normal\0");
        let (_resp1, outcome1) = session.handle_login_request(&req).unwrap();
        assert!(outcome1.is_none());
    }

    #[test]
    fn negotiated_keys_are_not_echoed_as_not_understood() {
        let addr = "192.0.2.1:3260".parse().unwrap();
        let mut session = LoginSession::new("iqn.2024-01.io.pxeasy:boot", addr);
        let req = login_request(
            b"InitiatorName=iqn.client\0\
              SessionType=Normal\0\
              MaxRecvDataSegmentLength=8192\0\
              MaxBurstLength=262144\0\
              FirstBurstLength=65536\0\
              InitialR2T=Yes\0\
              ImmediateData=No\0\
              HeaderDigest=None\0\
              DataDigest=None\0\
              AuthMethod=None\0",
        );

        let (resp, outcome) = session.handle_login_request(&req).unwrap();

        assert!(outcome.is_none());
        assert!(!resp
            .data
            .windows(b"=NotUnderstood\0".len())
            .any(|w| w == b"=NotUnderstood\0"));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let addr = "192.0.2.1:3260".parse().unwrap();
        let mut session = LoginSession::new("iqn.2024-01.io.pxeasy:boot", addr);
        let mut req = login_request(b"InitiatorName=iqn.client\0SessionType=Normal\0");
        req.version_max = 1;
        let err = session.handle_login_request(&req).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
