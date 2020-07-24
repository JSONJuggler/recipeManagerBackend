const _ = require("lodash");

module.exports = async (ctx, next) => {
  let role;

  if (ctx.request && ctx.request.header && ctx.request.header.authorization) {
    try {
      const { id, isAdmin = false } = await strapi.plugins[
        "users-permissions"
      ].services.jwt.getToken(ctx);
      console.log(isAdmin);
      if (id === undefined) {
        throw new Error("Invalid token: Token did not contain required fields");
      }

      if (isAdmin) {
        ctx.state.admin = await strapi
          .query("administrator", "admin")
          .findOne({ id }, []);
      } else {
        ctx.state.user = await strapi
          .query("user", "users-permissions")
          .findOne({ id }, ["role"]);
      }
    } catch (err) {
      // admins shouldnt end up here as they change things from the admin dashboard and
      // wont be getting non strapi jwts as those only come from the callbacks that are
      // fired off when using the actualy app on the front end
      ctx.state.user = await strapi
        .query("user", "users-permissions")
        .findOne({ id: "5f0901d4b324e22c15564c6c" }, ["role"]);

      // Retrieve `public` role.
      if (!role) {
        role = await strapi
          .query("role", "users-permissions")
          .findOne({ type: "public" }, []);
      }

      const route = ctx.request.route;
      const permission = await strapi
        .query("permission", "users-permissions")
        .findOne(
          {
            role: role.id,
            type: route.plugin || "application",
            controller: route.controller,
            action: route.action,
            enabled: true,
          },
          []
        );

      if (!permission) {
        return handleErrors(ctx, undefined, "forbidden");
      }
      console.log("allowing jwt");
      return await next();
      return handleErrors(ctx, err, "unauthorized");
    }

    if (ctx.state.admin) {
      if (ctx.state.admin.blocked === true) {
        return handleErrors(
          ctx,
          "Your account has been blocked by the administrator.",
          "unauthorized"
        );
      }

      ctx.state.user = ctx.state.admin;
      return await next();
    }

    if (!ctx.state.user) {
      return handleErrors(ctx, "User Not Found", "unauthorized");
    }

    role = ctx.state.user.role;

    if (role.type === "root") {
      return await next();
    }

    const store = await strapi.store({
      environment: "",
      type: "plugin",
      name: "users-permissions",
    });

    if (
      _.get(await store.get({ key: "advanced" }), "email_confirmation") &&
      !ctx.state.user.confirmed
    ) {
      return handleErrors(
        ctx,
        "Your account email is not confirmed.",
        "unauthorized"
      );
    }

    if (ctx.state.user.blocked) {
      return handleErrors(
        ctx,
        "Your account has been blocked by the administrator.",
        "unauthorized"
      );
    }
  }

  // Retrieve `public` role.
  if (!role) {
    role = await strapi
      .query("role", "users-permissions")
      .findOne({ type: "public" }, []);
  }

  const route = ctx.request.route;
  const permission = await strapi
    .query("permission", "users-permissions")
    .findOne(
      {
        role: role.id,
        type: route.plugin || "application",
        controller: route.controller,
        action: route.action,
        enabled: true,
      },
      []
    );

  if (!permission) {
    return handleErrors(ctx, undefined, "forbidden");
  }

  // Execute the policies.
  if (permission.policy) {
    return await strapi.plugins["users-permissions"].config.policies[
      permission.policy
    ](ctx, next);
  }

  // Execute the action.
  await next();
};

const handleErrors = (ctx, err = undefined, type) => {
  throw strapi.errors[type](err);
};
