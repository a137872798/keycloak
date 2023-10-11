package org.keycloak.authentication.authenticators.browser;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.KeycloakContext;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.services.validation.Validation;
import org.keycloak.utils.CaptchaUtils;
import org.keycloak.utils.MediaType;

import javax.imageio.ImageIO;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.keycloak.services.resources.LoginActionsService.SESSION_CODE;

/**
 * author: xuelei.guo
 * date: 2023/7/24 22:05
 */
public class CustomerUsernamePasswordForm extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(CustomerUsernamePasswordForm.class);

    private String loginHtmlName = "";


    protected void setLoginHtmlName(String loginHtmlName) {
        this.loginHtmlName = loginHtmlName;
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> parameters = context.getUriInfo().getQueryParameters();
        // 渲染验证码
        if (parameters.containsKey("refreshCaptcha")) {
            Response challengeResponse = captcha(context);
            context.challenge(challengeResponse);
            return;
        }
        super.action(context);
    }


    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String checkCaptcha = context.getAuthenticationSession().getClientNote("checkCaptcha");

        logger.info("checkCaptcha: " + checkCaptcha);

        // 代表需要校验验证码
        if (!Validation.isBlank(checkCaptcha) && Boolean.valueOf(checkCaptcha)) {

            String captcha = formData.get("captcha").get(0);

            // 参数中不包含验证码
            if (!formData.containsKey("captcha")
                    // 验证码错误
                    || !captcha.equalsIgnoreCase(context.getAuthenticationSession().getClientNote("captcha"))) {
                Response challengeResponse = challenge(context, "", Validation.FIELD_CAPTCHA);
                context.failureChallenge(AuthenticationFlowError.INVALID_CAPTCHA, challengeResponse);
                return false;
            }
        }

        // 验证码通过后 校验其他参数
        return super.validateUserAndPassword(context, formData);
    }

    private Response captcha(AuthenticationFlowContext context) {
        byte[] captchaChallengeAsJpeg = null;
        CaptchaUtils.Captcha captcha = CaptchaUtils.newCaptcha();
        ByteArrayOutputStream jpegOutputStream = new ByteArrayOutputStream();
        try {
            //使用生产的验证码字符串返回一个BufferedImage对象并转为byte写入到byte数组中
            BufferedImage challenge = captcha.getImage();
            ImageIO.write(challenge, "jpg", jpegOutputStream);
        } catch (IllegalArgumentException | IOException e) {
            logger.error("Failed to refresh captcha", e);
            return Response.serverError().build();
        }
        String text = captcha.getText();

        context.getAuthenticationSession().setClientNote("captcha",  text);

        String accessCode = context.generateAccessCode();

        KeycloakContext keycloakContext = context.getSession().getContext();
        String cookiePath = AuthenticationManager.getRealmCookiePath(keycloakContext.getRealm(), keycloakContext.getUri());
        CookieHelper.addCookie(SESSION_CODE, accessCode, cookiePath, null, null, -1, false, false);

        //定义response输出类型为image/jpeg类型，使用response输出流输出图片的byte数组
        captchaChallengeAsJpeg = jpegOutputStream.toByteArray();
        Response.ResponseBuilder builder = Response.status(Response.Status.OK)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .header("Expires", 0)
                .type("image/jpeg")
                .entity(captchaChallengeAsJpeg);
        return builder.build();
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        if (Validation.isBlank(loginHtmlName)) {
            logger.info("未设置loginHtmlName, 使用默认页面");
            return super.challenge(context, formData);
        }
        return loadHtml(context, Function.identity());
    }

    protected Response loadHtml(AuthenticationFlowContext context, Function<String, String> visitor) {
        // 根据会话信息生成一个code
        String accessCode = context.generateAccessCode();
        // 获取不包含 accessCode的url
        URI action = context.getRefreshExecutionUrl();

        File file = new File("/opt/bitnami/keycloak/themes/custom/dist/" + loginHtmlName + ".html");

        StringBuilder stringBuilder = new StringBuilder();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String a;
            while ((a = reader.readLine()) != null) {
                if (a.contains("sessionCode: ''")) {
                    a = a.replace("sessionCode: ''", "sessionCode: '" + accessCode + "'");
                }
                if (a.contains("reqUrl: ''")) {
                    a = a.replace("reqUrl: ''", "reqUrl: '" + action + "'");
                }
                if (a.contains("captchaUrl: ''")) {
                    Map<String, Object> param = new HashMap<>(1);
                    param.put("refreshCaptcha", true);
                    URI captchaUrl = URI.create(action.toString() + "&refreshCaptcha=true");
                    a = a.replace("captchaUrl: ''", "captchaUrl: '" + captchaUrl + "'");
                    context.getAuthenticationSession().setClientNote("checkCaptcha", "true");
                }
                a = visitor.apply(a);
                stringBuilder.append(a);
                stringBuilder.append("\n\r");
            }

        } catch (Exception e) {
            logger.error("Failed to load html", e);
            return Response.serverError().build();
        }
        String result = stringBuilder.toString();
        javax.ws.rs.core.MediaType mediaType = MediaType.TEXT_HTML_UTF_8_TYPE;
        Response.ResponseBuilder builder = Response.status(Response.Status.OK).type(mediaType).entity(result);
        return builder.build();
    }

    protected Response challenge(AuthenticationFlowContext context, String error) {
        return challenge(context, error, null);
    }

    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        String errorMsg;

        if (Validation.FIELD_CAPTCHA.equals(field)) {
            errorMsg = "验证码错误";
        } else if (Validation.FIELD_USERNAME.equals(field)) {
            errorMsg = "用户名不存在";
        } else if (Validation.FIELD_PASSWORD.equals(field)) {
            errorMsg = "密码错误";
        } else {
            errorMsg = "登录失败, 请检查用户名和密码";
        }

        return loadHtml(context, line -> {
            if (line.contains("<div class=\"formError\">")) {
                line = "<div class=\"formError\">" + errorMsg + "</div>";
            }
            return line;
        });
    }
}